//! A declaration that control never returns is part of the interface.
//!
//! Without it a body walk runs straight through the function that follows a
//! call to `err` or `abort`, because a call normally falls through and there
//! is no `ret` to stop at.

#[test]
fn the_table_declares_which_functions_never_return() {
    let table = r2abi::Prototypes::embedded();
    let err = table.get("err").expect("err is declared");
    assert!(err.noreturn, "err calls exit and never comes back");
    assert!(err.variadic);

    let memcpy = table.get("memcpy").expect("memcpy is declared");
    assert!(!memcpy.noreturn, "memcpy returns");
}
