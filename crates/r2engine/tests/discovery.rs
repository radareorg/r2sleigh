//! Discovery starts from what the container states and closes over the calls.
//!
//! The seeds were the shell's to gather, from the container it had parsed and
//! the stubs the engine had decoded; which addresses are believed to be
//! functions is the engine's question, so the whole answer is asked of it here.

mod common;

use common::{
    ARM_ENTRY, CALLER, FORKED, JOINED, Literal, ONE, THUMB_CALLED, THUMB_LEAF, TWO, VENEER,
};
use r2engine::discovery::Confidence;
use r2engine::program::OpenProgram;
use r2engine::query::{Listing, Stop};

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

fn spelled(program: &mut OpenProgram<Literal>, start: u64) -> Vec<String> {
    let listing = Listing {
        start,
        stop: Stop::After(3),
    };
    program
        .listing(listing)
        .expect("listing")
        .value
        .iter()
        .map(|line| {
            line.syntax
                .as_ref()
                .map(|syntax| syntax.text())
                .unwrap_or_default()
        })
        .collect()
}

#[test]
fn a_function_reached_only_by_a_call_is_in_the_instruction_set_the_call_enters() {
    // Nothing states the two Thumb functions: `blx` enters the first in Thumb
    // and its `bl` keeps the second there.
    let found = OpenProgram::of(Literal::arm_thumb())
        .functions()
        .expect("discovery runs")
        .iter()
        .map(|one| (one.address, one.confidence, one.thumb))
        .collect::<Vec<_>>();
    assert_eq!(
        found,
        [
            (ARM_ENTRY, Confidence::Stated, false),
            (THUMB_CALLED, Confidence::Called, true),
            (THUMB_LEAF, Confidence::Called, true),
            (VENEER, Confidence::Stated, true),
        ]
    );
    // A listing answers the same whether or not discovery was asked first.
    let mut cold = OpenProgram::of(Literal::arm_thumb());
    let first = spelled(&mut cold, THUMB_CALLED);
    let mut warm = OpenProgram::of(Literal::arm_thumb());
    warm.functions().expect("discovery runs");
    assert_eq!(first, spelled(&mut warm, THUMB_CALLED));
    assert_eq!(first[0], "push {r4, lr}", "{first:?}");
    assert!(first[1].starts_with("bl "), "{first:?}");
    assert_eq!(spelled(&mut cold, ARM_ENTRY)[1], "bx lr");
    // A mapping symbol switches the instruction set inside one function.
    assert_eq!(spelled(&mut cold, VENEER)[..2], ["bx pc", "mov r8, r8"]);
    assert_eq!(spelled(&mut cold, VENEER + 4)[0], "bx lr");
    // The ARM caller reads its Thumb callee's body in Thumb.
    let prepared = cold.prepared(ARM_ENTRY).expect("prepared");
    assert_eq!(prepared.unread(), [], "{:?}", prepared.unread());
}
