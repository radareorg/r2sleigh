//! A request can be stopped once it has started.
//!
//! Three sites used to mint an execution control inline and drop the owner, so
//! every native request carried tokens nothing could reach. Nothing had ever
//! run under a cancellation, which is why this exists.

use std::path::PathBuf;

use r2engine::program::OpenProgram;
use r2engine::{EngineCancellationToken, EngineExecutionControl};

fn pinned() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/coverage/pinned/hashes_gcc_x64_O2")
}

const FUNCTION: u64 = 0x401330;

fn opened() -> OpenProgram {
    let mut program =
        OpenProgram::open(pinned().to_str().expect("the fixture path is text")).expect("it opens");
    program.ensure_assembled(FUNCTION).expect("it assembles");
    program
}

#[test]
fn a_cancelled_request_refuses_rather_than_answering() {
    let mut program = opened();
    let cancellation = EngineCancellationToken::default();
    program.begin_request(EngineExecutionControl::with_cancellation(
        cancellation.clone(),
    ));
    cancellation.cancel();
    let target = program.target(FUNCTION).expect("the machine is described");
    assert!(
        program.analysed(&target, FUNCTION).is_err(),
        "a cancelled request produced an answer"
    );
}

#[test]
fn the_next_request_does_not_inherit_the_last_one_s_stop() {
    let mut program = opened();
    let cancellation = EngineCancellationToken::default();
    program.begin_request(EngineExecutionControl::with_cancellation(
        cancellation.clone(),
    ));
    cancellation.cancel();
    {
        let target = program.target(FUNCTION).expect("the machine is described");
        let _ = program.analysed(&target, FUNCTION);
    }
    program.begin_request(EngineExecutionControl::default());
    let target = program.target(FUNCTION).expect("the machine is described");
    assert!(
        program.analysed(&target, FUNCTION).is_ok(),
        "a stop meant for one request refused the next"
    );
}
