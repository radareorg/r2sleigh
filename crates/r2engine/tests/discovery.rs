//! Discovery starts from what the container states and closes over the calls.
//!
//! The seeds were the shell's to gather, from the container it had parsed and
//! the stubs the engine had decoded; which addresses are believed to be
//! functions is the engine's question, so the whole answer is asked of it here.

mod common;

use common::{CALLER, FORKED, JOINED, Literal, ONE, TWO};
use r2engine::discovery::Confidence;
use r2engine::program::OpenProgram;

fn believed(program: &mut OpenProgram<Literal>) -> Vec<(u64, Confidence)> {
    program
        .functions()
        .expect("discovery runs")
        .iter()
        .map(|one| (one.address, one.confidence))
        .collect()
}

#[test]
fn every_function_the_container_states_is_found_as_stated() {
    let mut program = OpenProgram::of(Literal::new());
    assert_eq!(
        believed(&mut program),
        [
            (ONE, Confidence::Stated),
            (CALLER, Confidence::Stated),
            (TWO, Confidence::Stated),
            (FORKED, Confidence::Stated),
            (JOINED, Confidence::Stated)
        ]
    );
}

#[test]
fn a_function_nothing_states_is_found_by_its_caller() {
    let mut program = OpenProgram::of(Literal::new().stripped_of("one"));
    assert_eq!(
        believed(&mut program),
        [
            (ONE, Confidence::Called),
            (CALLER, Confidence::Stated),
            (TWO, Confidence::Stated),
            (FORKED, Confidence::Stated),
            (JOINED, Confidence::Stated)
        ]
    );
}
