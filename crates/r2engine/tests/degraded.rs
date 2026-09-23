//! A degraded answer says what it could not read.
//!
//! A callee whose body could not be walked or prepared used to be skipped in
//! silence, so a call rendered from the call site alone looked exactly like a
//! call rendered against a proven interface.

mod common;

use common::{CALLER, ONE, opened};
use r2engine::native::Unreadable;

#[test]
fn a_callee_that_cannot_be_walked_is_named() {
    let mut program = opened();
    // `0x06` encodes nothing in long mode, so the callee's first instruction
    // is not an instruction and its body cannot be walked at all.
    program.source_mut().write(ONE, &[0x06]);
    let prepared = program.prepared(CALLER).expect("the caller still prepares");
    let named = prepared
        .unread()
        .iter()
        .find(|callee| callee.address == ONE)
        .expect("the callee whose body is not code is reported");
    assert_eq!(named.reason, Unreadable::NotWalked);
    assert_eq!(format!("{named}"), "0x1000: its body could not be walked");
}

#[test]
fn a_program_whose_callees_all_read_reports_none() {
    let mut program = opened();
    let prepared = program.prepared(CALLER).expect("the caller prepares");
    assert_eq!(prepared.unread(), &[]);
}
