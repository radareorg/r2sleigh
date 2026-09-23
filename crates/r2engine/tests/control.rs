//! A request can be stopped once it has started.
//!
//! Three sites used to mint an execution control inline and drop the owner, so
//! every native request carried tokens nothing could reach. Nothing had ever
//! run under a cancellation, which is why this exists.

mod common;

use common::{ONE, opened};
use r2engine::{EngineCancellationToken, EngineExecutionControl};

#[test]
fn a_cancelled_request_refuses_rather_than_answering() {
    let mut program = opened();
    let cancellation = EngineCancellationToken::default();
    program.begin_request(EngineExecutionControl::with_cancellation(
        cancellation.clone(),
    ));
    cancellation.cancel();
    assert!(
        program.prepared(ONE).is_err(),
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
    let _ = program.prepared(ONE);
    program.begin_request(EngineExecutionControl::default());
    assert!(
        program.prepared(ONE).is_ok(),
        "a stop meant for one request refused the next"
    );
}
