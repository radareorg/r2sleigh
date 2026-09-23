//! Discovery starts from what the container states and closes over the calls.
//!
//! The seeds were the shell's to gather, from the container it had parsed and
//! the stubs the engine had decoded; which addresses are believed to be
//! functions is the engine's question, so the whole answer is asked of it here.

mod common;

use common::{
    ARM_ENTRY, CALLER, FORKED, JOINED, Literal, ONE, PASSES, STEPPED, THUMB_CALLED, THUMB_LEAF,
    TWO, VENEER,
};
use r2engine::discovery::Confidence;
use r2engine::program::{OpenProgram, Symbol, SymbolKind};
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
            (JOINED, Confidence::Stated),
            (PASSES, Confidence::Stated),
            (STEPPED, Confidence::Stated)
        ]
    );
}

#[test]
fn a_function_handed_to_an_import_through_its_slot_is_found_as_handed() {
    // `atexit` is declared to take a function; the call reads the slot the
    // relocation names, and only that says which import is called.
    let mut program = OpenProgram::of(Literal::new().stripped_of("two").importing("atexit"));
    // lea rdi, [rip + 9] (two); call qword [rip + 0x7b] (the slot); ret
    program.source_mut().write(
        CALLER,
        &[
            0x48, 0x8d, 0x3d, 0x09, 0, 0, 0, 0xff, 0x15, 0x7b, 0, 0, 0, 0xc3,
        ],
    );
    assert!(
        believed(&mut program).contains(&(TWO, Confidence::Handed)),
        "{:?}",
        believed(&mut program)
    );
}

#[test]
fn a_data_symbol_or_an_import_s_symbol_states_no_function() {
    let symbol = |name: &str, kind, defined| Symbol {
        name: name.to_owned(),
        vaddr: TWO + 0x8,
        size: 0,
        kind,
        defined,
        thumb: false,
    };
    for literal in [
        Literal::new().declaring(symbol("table", SymbolKind::Data, true)),
        Literal::new().declaring(symbol("imported", SymbolKind::Function, false)),
    ] {
        assert_eq!(
            believed(&mut OpenProgram::of(literal)),
            believed(&mut OpenProgram::of(Literal::new()))
        );
    }
}

#[test]
fn every_reference_every_believed_body_makes_is_indexed_once_in_order() {
    // `one` and `two` each read a word the program's `.text` holds, and
    // `caller` still reaches `one` so discovery walks it.
    let mut program = OpenProgram::of(Literal::new().stripped_of("one"));
    // mov eax, dword [stepped + 8]; ret
    program
        .source_mut()
        .write(ONE, &[0x8b, 0x04, 0x25, 0x88, 0x10, 0x00, 0x00, 0xc3]);
    // mov eax, dword [stepped]; ret
    program
        .source_mut()
        .write(TWO, &[0x8b, 0x04, 0x25, 0x80, 0x10, 0x00, 0x00, 0xc3]);
    let facts = program.references().expect("the index builds").value.facts;
    let mut sorted = facts.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(facts, sorted);
    let read = facts
        .iter()
        .filter(|one| [ONE, TWO].contains(&one.from))
        .map(|one| (one.from, one.to, one.kind))
        .collect::<Vec<_>>();
    assert_eq!(
        read,
        [
            (ONE, STEPPED + 8, r2ssa::DataRefKind::Data),
            (TWO, STEPPED, r2ssa::DataRefKind::Data)
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
            (JOINED, Confidence::Stated),
            (PASSES, Confidence::Stated),
            (STEPPED, Confidence::Stated)
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
