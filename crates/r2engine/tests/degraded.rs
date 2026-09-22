//! A degraded answer says what it could not read.
//!
//! A callee whose body could not be walked or prepared used to be skipped in
//! silence, so a call rendered from the call site alone looked exactly like a
//! call rendered against a proven interface.

use std::path::PathBuf;

use r2engine::native::Unreadable;
use r2engine::program::OpenProgram;

fn pinned() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/coverage/pinned/hashes_gcc_x64_O2")
}

const MAIN: u64 = 0x401050;
const FNV1A32: u64 = 0x401330;

fn opened() -> OpenProgram {
    OpenProgram::open(pinned().to_str().expect("the fixture path is text")).expect("it opens")
}

#[test]
fn a_callee_that_cannot_be_walked_is_named() {
    let mut program = opened();
    // `0x06` encodes nothing in long mode, so the callee's first instruction
    // is not an instruction and its body cannot be walked at all.
    program.image.write(FNV1A32, &[0x06]).expect("it patches");
    program.ensure_assembled(MAIN).expect("it assembles");
    let target = program.target(MAIN).expect("the machine is described");
    let prepared = program
        .analysed(&target, MAIN)
        .expect("main still prepares");
    let named = prepared
        .unread()
        .iter()
        .find(|callee| callee.address == FNV1A32)
        .expect("the callee whose body is not code is reported");
    assert_eq!(named.reason, Unreadable::NotWalked);
    assert_eq!(format!("{named}"), "0x401330: its body could not be walked");
}

#[test]
fn a_program_whose_callees_all_read_reports_none() {
    let mut program = opened();
    program.ensure_assembled(MAIN).expect("it assembles");
    let target = program.target(MAIN).expect("the machine is described");
    let prepared = program.analysed(&target, MAIN).expect("main prepares");
    assert_eq!(prepared.unread(), &[]);
}
