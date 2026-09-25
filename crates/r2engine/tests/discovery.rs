//! Discovery starts from what the container states and closes over the calls.
//!
//! The seeds were the shell's to gather, from the container it had parsed and
//! the stubs the engine had decoded; which addresses are believed to be
//! functions is the engine's question, so the whole answer is asked of it here.

mod common;

use common::{
    ARM_ENTRY, BASE, CALLER, FORKED, GLIBC, JOINED, Literal, ONE, PASSES, STEPPED, THUMB_CALLED,
    THUMB_LEAF, TWO, VENEER,
};
use r2engine::discovery::Confidence;
use r2engine::program::{OpenProgram, Symbol, SymbolKind};
use r2engine::query::{Listing, Role, Stop};

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
    let mut program = OpenProgram::of(
        Literal::new()
            .stripped_of("two")
            .importing("atexit")
            .running_on(GLIBC),
    );
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
        ..Symbol::default()
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
    let index = program.references().expect("the index builds").value;
    let facts = index.facts();
    assert!(facts.is_sorted());
    assert!(
        facts
            .windows(2)
            .all(|pair| (pair[0].from, pair[0].to, pair[0].role)
                != (pair[1].from, pair[1].to, pair[1].role))
    );
    let read = facts
        .iter()
        .filter(|one| [ONE, TWO].contains(&one.from))
        .map(|one| (one.from, one.to, one.role))
        .collect::<Vec<_>>();
    let word = Role::Read { width: 4 };
    assert_eq!(read, [(ONE, STEPPED + 8, word), (TWO, STEPPED, word)]);
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

/// `wrap: mov edi, 1; call exit`, then `user: call wrap`, then `next`, which only `other` calls.
const WRAPPED: [u8; 0xa0] = {
    let mut code = [0xcc; 0xa0];
    let runs: [(usize, &[u8]); 5] = [
        (0x00, &[0xbf, 0x01, 0, 0, 0, 0xe8, 0x86, 0, 0, 0]), // wrap: mov edi, 1; call the stub
        (0x0a, &[0xe8, 0xf1, 0xff, 0xff, 0xff]),             // user: call wrap
        (0x0f, &[0xb8, 0x02, 0, 0, 0, 0xc3]),                // next: mov eax, 2; ret
        (0x15, &[0xe8, 0xf5, 0xff, 0xff, 0xff, 0xc3]),       // other: call next; ret
        (0x90, &[0xff, 0x25, 0x02, 0, 0, 0]),                // the stub: jmp qword [rip + 2]
    ];
    let mut index = 0;
    while index < runs.len() {
        let (at, run) = runs[index];
        let mut offset = 0;
        while offset < run.len() {
            code[at + offset] = run[offset];
            offset += 1;
        }
        index += 1;
    }
    code
};

/// `spin: jmp spin`, then `caller: call spin; mov eax, 1; ret`.
const SPINS: &[u8] = &[
    0xeb, 0xfe, 0xe8, 0xf9, 0xff, 0xff, 0xff, 0xb8, 1, 0, 0, 0, 0xc3,
];
/// A defined `exit: ret`, then `caller: call exit; mov eax, 1; ret`.
const DEFINES_EXIT: &[u8] = &[0xc3, 0xe8, 0xfa, 0xff, 0xff, 0xff, 0xb8, 1, 0, 0, 0, 0xc3];
/// `ind: jmp rax`, then `caller: call ind; mov eax, 1; ret`.
const STOPS: &[u8] = &[
    0xff, 0xe0, 0xe8, 0xf9, 0xff, 0xff, 0xff, 0xb8, 1, 0, 0, 0, 0xc3,
];
/// `f: call g; ret`, padding, then `g: call f; ret`.
const MUTUAL: &[u8] = &[
    0xe8, 0x0b, 0, 0, 0, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xe8,
    0xeb, 0xff, 0xff, 0xff, 0xc3,
];

/// Where a function's blocks end, and whether the program proves it never returns.
fn extent(program: &mut OpenProgram<Literal>, entry: u64) -> (u64, bool) {
    let info = program.function_info(entry).expect("it is described");
    (info.max_addr(), info.noreturn)
}

#[test]
fn a_caller_of_a_function_that_only_calls_exit_ends_at_that_call() {
    let (wrap, user, next, other) = (BASE, BASE + 0xa, BASE + 0xf, BASE + 0x15);
    let literal = || {
        let functions = [("wrap", wrap, 10), ("user", user, 5), ("other", other, 6)];
        Literal::of_code(&WRAPPED, &functions).importing("exit")
    };
    let mut cold = OpenProgram::of(literal());
    // `next` is nobody's entry but a call's, so only knowing `wrap` never returns stops `user` there.
    assert_eq!(extent(&mut cold, user), (next, true));
    assert_eq!(extent(&mut cold, wrap), (user, true));
    assert_eq!(extent(&mut cold, next), (other, false));
    // Discovery asked first derives the same answers for the whole program.
    let mut warm = OpenProgram::of(literal());
    let found = believed(&mut warm);
    assert!(found.contains(&(next, Confidence::Called)), "{found:?}");
    assert_eq!(extent(&mut warm, user), (next, true));
}

#[test]
fn a_call_to_a_function_that_spins_forever_ends_its_caller() {
    let (spin, caller) = (BASE, BASE + 2);
    let functions = [("spin", spin, 2), ("caller", caller, 11)];
    let mut program = OpenProgram::of(Literal::of_code(SPINS, &functions));
    assert_eq!(extent(&mut program, caller), (caller + 5, true));
    assert_eq!(extent(&mut program, spin), (caller, true));
}

#[test]
fn a_defined_function_named_exit_that_returns_is_called_past() {
    let (exit, caller) = (BASE, BASE + 1);
    let functions = [("exit", exit, 1), ("caller", caller, 11)];
    let mut program = OpenProgram::of(Literal::of_code(DEFINES_EXIT, &functions));
    assert_eq!(extent(&mut program, caller), (caller + 11, false));
    assert_eq!(extent(&mut program, exit), (caller, false));
}

#[test]
fn functions_that_only_call_each_other_never_return() {
    let (f, g) = (BASE, BASE + 0x10);
    let functions = [("f", f, 6), ("g", g, 6)];
    let mut program = OpenProgram::of(Literal::of_code(MUTUAL, &functions));
    assert_eq!(extent(&mut program, f), (f + 5, true));
    assert_eq!(extent(&mut program, g), (g + 5, true));
}

#[test]
fn a_callee_whose_walk_stops_at_an_indirect_branch_may_return() {
    let (ind, caller) = (BASE, BASE + 2);
    let functions = [("ind", ind, 2), ("caller", caller, 11)];
    let mut program = OpenProgram::of(Literal::of_code(STOPS, &functions));
    assert_eq!(extent(&mut program, caller), (caller + 11, false));
    assert!(!extent(&mut program, ind).1);
}

/// `spin: b spin`, then `caller: cmp r0, #0; blne spin; bx lr`.
const PREDICATED: &[u8] = &[
    0xfe, 0xff, 0xff, 0xea, 0x00, 0x00, 0x50, 0xe3, 0xfc, 0xff, 0xff, 0x1b, 0x1e, 0xff, 0x2f, 0xe1,
];

#[test]
fn a_predicated_call_to_a_function_that_never_returns_goes_on_when_its_predicate_fails() {
    let (spin, caller) = (BASE, BASE + 4);
    let functions = [("spin", spin, 4), ("caller", caller, 12)];
    let literal = Literal::of_code(PREDICATED, &functions).in_arm();
    let mut program = OpenProgram::of(literal);
    assert_eq!(extent(&mut program, spin), (caller, true));
    assert_eq!(extent(&mut program, caller), (caller + 12, false));
}

#[test]
fn a_function_that_runs_on_into_another_returns_what_that_one_returns() {
    // `f: call ind` runs on into `g: mov eax, 1; ret` once `ind`, stopped at `jmp rax`, may return.
    let (ind, f, g) = (BASE, BASE + 2, BASE + 7);
    let functions = [("ind", ind, 2), ("f", f, 5), ("g", g, 6)];
    let literal = || Literal::of_code(STOPS, &functions);
    let mut cold = OpenProgram::of(literal());
    assert_eq!(extent(&mut cold, f), (g, false));
    let mut warm = OpenProgram::of(literal());
    believed(&mut warm);
    assert_eq!(extent(&mut warm, f), (g, false));
}
