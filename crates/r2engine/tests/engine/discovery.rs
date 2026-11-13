//! Discovery starts from what the container states and closes over the calls.
//!
//! The seeds were the shell's to gather, from the container it had parsed and
//! the stubs the engine had decoded; which addresses are believed to be
//! functions is the engine's question, so the whole answer is asked of it here.

use crate::common;

use common::{
    ARM_ENTRY, BASE, CALLER, FORKED, GLIBC, JOINED, Literal, ONE, PASSES, PLT_SEC_STUB, STEPPED,
    THUMB_CALLED, THUMB_LEAF, TWO, VENEER,
};
use r2abi::frames::FrameEntry;
use r2engine::discovery::Basis;
use r2engine::program::{EntryKind, OpenProgram, Symbol, SymbolKind};
use r2engine::query::{Listing, Role, Stop};

const CALLED: FrameEntry = FrameEntry::Called;

fn believed(program: &mut OpenProgram<Literal>) -> Vec<(u64, Basis)> {
    program
        .functions()
        .expect("discovery runs")
        .iter()
        .map(|one| (one.address, one.confidence.basis))
        .collect()
}

#[test]
fn every_function_the_container_states_is_found_as_stated() {
    let mut program = OpenProgram::of(Literal::new());
    assert_eq!(
        believed(&mut program),
        [
            (ONE, Basis::Stated),
            (CALLER, Basis::Stated),
            (TWO, Basis::Stated),
            (FORKED, Basis::Stated),
            (JOINED, Basis::Stated),
            (PASSES, Basis::Stated),
            (STEPPED, Basis::Stated)
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
        believed(&mut program).contains(&(TWO, Basis::Handed)),
        "{:?}",
        believed(&mut program)
    );
}

#[test]
fn a_data_symbol_or_an_import_s_symbol_states_no_function() {
    let symbol = |name: &str, kind, defined| Symbol {
        name: name.into(),
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

/// A frame the call-frame information states begins a function, which survives a strip; a frame
/// holding a linkage stub is the stub table's and begins none (ROADMAP I).
#[test]
fn a_stated_frame_begins_a_function_and_the_stub_table_s_does_not() {
    let stripped = || Literal::new().stripped_of("stepped");
    let unstated = believed(&mut OpenProgram::of(stripped()));
    assert!(!unstated.iter().any(|(address, _)| *address == STEPPED));
    let framed = believed(&mut OpenProgram::of(
        stripped().unwinding(STEPPED..STEPPED + 0xc, CALLED),
    ));
    assert!(framed.contains(&(STEPPED, Basis::Stated)), "{framed:x?}");

    let plt = believed(&mut OpenProgram::of(Literal::plt()));
    let framed_plt = believed(&mut OpenProgram::of(
        Literal::plt().unwinding(BASE..BASE + 0x20, CALLED),
    ));
    assert_eq!(framed_plt, plt);
}

/// A program with an import slot elsewhere, whose frame over a section holding only an indirect
/// jump begins a function: no jump there is shown to read a loader word, so it is no linkage code.
#[test]
fn a_frame_over_an_unplaced_indirect_jump_begins_a_function() {
    let program = Literal::tail_section().unwinding(BASE..BASE + 2, CALLED);
    let found = believed(&mut OpenProgram::of(program));
    assert!(
        found.iter().any(|(address, _)| *address == BASE),
        "{found:x?}"
    );
}

/// `wrapper` (stated): `mov eax, 1; jmp tail`. `tail`, stated only by a frame: `add eax, 1; ret`.
const TAIL_JUMP: &[u8] = &[
    0xb8, 0x01, 0x00, 0x00, 0x00, // 0x1000 mov eax, 1
    0xeb, 0x09, // 0x1005 jmp 0x1010
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, //
    0x83, 0xc0, 0x01, // 0x1010 add eax, 1
    0xc3, // 0x1013 ret
];

/// A tail jump into a function its frame alone states ends the body there (audit W4); into a
/// fragment entered mid-function, as GCC's `.cold` is, the body runs on through it.
#[test]
fn a_tail_jump_ends_at_a_framed_function_and_runs_on_through_a_fragment() {
    const TAIL: u64 = BASE + 0x10;
    let framed = |entry| {
        let literal = Literal::of_code(TAIL_JUMP, &[("wrapper", BASE, 7)]);
        OpenProgram::of(literal.unwinding(TAIL..TAIL + 4, entry))
    };

    let mut called = framed(FrameEntry::Called);
    assert_eq!(
        believed(&mut called),
        [(BASE, Basis::Stated), (TAIL, Basis::Stated)]
    );
    assert_eq!(called.functions_holding(TAIL).expect("surveyed"), [TAIL]);
    let extents = called.function_extents().expect("surveyed");
    assert_eq!((extents[&BASE].blocks, extents[&BASE].bytes), (1, 7));

    let mut fragment = framed(FrameEntry::MidFunction);
    assert_eq!(believed(&mut fragment), [(BASE, Basis::Stated)]);
    assert_eq!(fragment.functions_holding(TAIL).expect("surveyed"), [BASE]);
    let extents = fragment.function_extents().expect("surveyed");
    assert_eq!((extents[&BASE].blocks, extents[&BASE].bytes), (2, 11));
}

#[test]
fn a_frame_over_a_cet_plt_begins_no_function_though_the_plt_names_no_stub() {
    let mut unframed = OpenProgram::of(Literal::plt_cet());
    let plt = believed(&mut unframed);
    let named = unframed.imports();
    assert_eq!(
        named
            .stubs
            .get(&PLT_SEC_STUB)
            .map(|stub| stub.symbol.as_str()),
        Some("_Exit")
    );
    assert!(named.stubs.range(BASE..PLT_SEC_STUB).next().is_none());
    // The `.plt` frame holds PLT0 and a lazy entry; with no stub in it, only the section says so.
    let framed = believed(&mut OpenProgram::of(
        Literal::plt_cet().unwinding(BASE..PLT_SEC_STUB, CALLED),
    ));
    assert_eq!(framed, plt);
    assert!(
        !framed.iter().any(|(address, _)| *address == BASE),
        "{framed:x?}"
    );
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

/// An initialiser the container lists outside every segment, and a `call 0` in a body, begin no
/// function: each is dropped and recorded with its reason (audit W29).
#[test]
fn a_start_that_holds_no_code_is_no_function_and_is_recorded() {
    const NOWHERE: u64 = 0x5000;
    let literal = Literal::new().entering(NOWHERE, EntryKind::Init);
    let mut program = OpenProgram::of(literal);
    // caller: call 0 (rel32 = 0 - 0x1015); ret
    (program.source_mut()).write(CALLER, &[0xe8, 0xeb, 0xef, 0xff, 0xff, 0xc3]);
    let found = believed(&mut program);
    assert!(
        !found
            .iter()
            .any(|(address, _)| [0, NOWHERE].contains(address)),
        "{found:x?}"
    );
    let placeless = program.placeless_starts().expect("surveyed");
    let reasons = (placeless.iter())
        .map(|(address, confidence)| (*address, confidence.basis))
        .collect::<Vec<_>>();
    assert_eq!(reasons, [(0, Basis::Called), (NOWHERE, Basis::Stated)]);
    // Nothing proves the call never returns, so the caller's body runs on to its `ret`.
    let extents = program.function_extents().expect("surveyed");
    assert_eq!(extents[&CALLER].bytes, 6);
}

#[test]
fn a_function_nothing_states_is_found_by_its_caller() {
    let mut program = OpenProgram::of(Literal::new().stripped_of("one"));
    assert_eq!(
        believed(&mut program),
        [
            (ONE, Basis::Called),
            (CALLER, Basis::Stated),
            (TWO, Basis::Stated),
            (FORKED, Basis::Stated),
            (JOINED, Basis::Stated),
            (PASSES, Basis::Stated),
            (STEPPED, Basis::Stated)
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
        .map(|one| (one.address, one.confidence.basis, one.thumb))
        .collect::<Vec<_>>();
    assert_eq!(
        found,
        [
            (ARM_ENTRY, Basis::Stated, false),
            (THUMB_CALLED, Basis::Called, true),
            (THUMB_LEAF, Basis::Called, true),
            (VENEER, Basis::Stated, true),
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
    (info.max_addr(), info.noreturn.is_some())
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
    assert!(found.contains(&(next, Basis::Called)), "{found:?}");
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

/// `trap: ud2`, then `caller: call trap; mov eax, 1; ret`.
const TRAPS: &[u8] = &[
    0x0f, 0x0b, 0xe8, 0xf9, 0xff, 0xff, 0xff, 0xb8, 1, 0, 0, 0, 0xc3,
];

/// `ud2` raises an invalid-opcode exception and does not come back (audit W23): its callee never
/// returns, where its `goto [target]` used to read as an unresolved indirect branch.
#[test]
fn a_call_to_a_function_that_executes_ud2_ends_its_caller() {
    let (trap, caller) = (BASE, BASE + 2);
    let functions = [("trap", trap, 2), ("caller", caller, 11)];
    let mut program = OpenProgram::of(Literal::of_code(TRAPS, &functions));
    assert_eq!(extent(&mut program, trap), (caller, true));
    assert_eq!(extent(&mut program, caller), (caller + 5, true));
}

/// `trap: int3`, then `caller: call trap; mov eax, 1; ret`.
const BREAKS: &[u8] = &[0xcc, 0xe8, 0xfa, 0xff, 0xff, 0xff, 0xb8, 1, 0, 0, 0, 0xc3];

/// `int3` raises #BP, which Sleigh ends with `return [0]`: a trap, so a call to a function that
/// executes it ends its caller (D352).
#[test]
fn a_call_to_a_function_that_executes_int3_ends_its_caller() {
    let (trap, caller) = (BASE, BASE + 1);
    let functions = [("trap", trap, 1), ("caller", caller, 11)];
    let mut program = OpenProgram::of(Literal::of_code(BREAKS, &functions));
    assert_eq!(extent(&mut program, trap), (caller, true));
    assert_eq!(extent(&mut program, caller), (caller + 5, true));
}

/// `fatal: ret`, then `caller: call fatal; mov eax, 1; ret`.
const DECLARED_FATAL: &[u8] = &[0xc3, 0xe8, 0xfa, 0xff, 0xff, 0xff, 0xb8, 1, 0, 0, 0, 0xc3];

/// Debug information that declares `fatal` `DW_AT_noreturn` (diffutils `try_help`) ends a call to it
/// with no premise (D255); with none, the body's `ret` comes back.
#[test]
fn a_call_to_a_function_its_debug_information_declares_noreturn_ends_its_caller() {
    let (fatal, caller) = (BASE, BASE + 1);
    let functions = [("fatal", fatal, 1), ("caller", caller, 11)];
    let prototype = r2abi::Prototype {
        name: "fatal".to_owned(),
        noreturn: true,
        ..r2abi::Prototype::default()
    };
    let mut declarations = r2abi::Declarations::new(r2abi::TypeGraph::new());
    declarations.declare_function(fatal, prototype);
    let literal = Literal::of_code(DECLARED_FATAL, &functions);
    let mut declared = OpenProgram::of(literal.with_declarations(declarations));
    assert_eq!(extent(&mut declared, caller), (caller + 5, true));
    let mut bare = OpenProgram::of(Literal::of_code(DECLARED_FATAL, &functions));
    assert_eq!(extent(&mut bare, caller), (caller + 11, false));
}

/// `sys: int 0x80; ret`, then `caller: call sys; mov eax, 1; ret`.
const INTERRUPTS: &[u8] = &[
    0xcd, 0x80, 0xc3, 0xe8, 0xf8, 0xff, 0xff, 0xff, 0xb8, 1, 0, 0, 0, 0xc3,
];

/// Any other vector stays the call through it Sleigh writes, which comes back (D352).
#[test]
fn a_call_to_a_function_that_interrupts_through_another_vector_comes_back() {
    let (sys, caller) = (BASE, BASE + 3);
    let functions = [("sys", sys, 3), ("caller", caller, 11)];
    let mut program = OpenProgram::of(Literal::of_code(INTERRUPTS, &functions));
    assert_eq!(extent(&mut program, caller), (caller + 11, false));
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

/// `trap: ud2`, then `caller: test edi, edi; je 1f; call trap; 1: mov eax, 1; ret`.
const GUARDED_TRAP: &[u8] = &[
    0x0f, 0x0b, 0x85, 0xff, 0x74, 0x05, 0xe8, 0xf5, 0xff, 0xff, 0xff, 0xb8, 1, 0, 0, 0, 0xc3,
];

fn rendered_caller(literal: Literal) -> String {
    let mut open = OpenProgram::of(literal);
    let rendered = open.rendered(BASE + 2).expect("it renders");
    rendered.response.output.into_text()
}

/// A callee only the walk finds reaching no return ends its call's block, but the exit is unnamed:
/// the "never" is a bound (RULING 1.4, D255). A declared one names it.
#[test]
fn a_call_to_a_never_no_statement_makes_leaves_its_exit_unnamed() {
    let functions = [("trap", BASE, 2), ("caller", BASE + 2, 15)];
    let derived = rendered_caller(Literal::of_code(GUARDED_TRAP, &functions));
    let prototype = r2abi::Prototype {
        name: "trap".to_owned(),
        noreturn: true,
        ..r2abi::Prototype::default()
    };
    let mut declarations = r2abi::Declarations::new(r2abi::TypeGraph::new());
    declarations.declare_function(BASE, prototype);
    let literal = Literal::of_code(GUARDED_TRAP, &functions).with_declarations(declarations);
    let declared = rendered_caller(literal);
    assert!(
        derived.contains("1 call ends where no return was reached (unproven)"),
        "{derived}"
    );
    assert!(
        declared.contains("__attribute__((noreturn)) void trap"),
        "{declared}"
    );
    assert!(!declared.contains("unproven)"), "{declared}");
}

/// `fail: mov ecx, 7; int 0x29; ret`, then `caller: call fail; mov eax, 1; ret`.
const FASTFAILS: &[u8] = &[
    0xb9, 7, 0, 0, 0, 0xcd, 0x29, 0xc3, 0xe8, 0xf3, 0xff, 0xff, 0xff, 0xb8, 1, 0, 0, 0, 0xc3,
];

/// Windows states `int 0x29` (`__fastfail`) never returns, so a PE's call to `fail` ends its
/// caller; under Linux the same vector is a call that comes back (D229).
#[test]
fn a_call_to_a_function_that_fastfails_ends_its_caller_in_a_pe() {
    let (fail, caller) = (BASE, BASE + 8);
    let functions = [("fail", fail, 8), ("caller", caller, 11)];
    let mut pe = OpenProgram::of(Literal::of_code(FASTFAILS, &functions).pe());
    assert_eq!(extent(&mut pe, fail), (fail + 7, true));
    assert_eq!(extent(&mut pe, caller), (caller + 5, true));
    let mut elf = OpenProgram::of(Literal::of_code(FASTFAILS, &functions));
    assert_eq!(extent(&mut elf, caller), (caller + 11, false));
}

/// A table switch whose arms return `g()` (`mov eax, 1`) and whose default arm calls `ends`:
/// the import `exit` at the stub, or the body `trap` (`ud2`) at 0x1036.
///
/// ```text
///   1000  cmp edi, 3; ja 0x1020; mov edi, edi; jmp [rdi*8 + 0x1040]
///   100e  call g; ret                ; cases 0, 1, 2 at 100e, 1014, 101a; case 3 at 1028
///   1020  xor edi, edi; call ends    ; the default arm
///   1030  g: mov eax, 1; ret
///   1036  trap: ud2
/// ```
fn switch_ending_at(ends: u64) -> &'static [u8] {
    let mut code = vec![0xcc; 0xa0];
    code[..0x0e].copy_from_slice(&[
        0x83, 0xff, 0x03, 0x77, 0x1b, 0x89, 0xff, 0xff, 0x24, 0xfd, 0x40, 0x10, 0x00, 0x00,
    ]);
    for arm in [0x0e, 0x14, 0x1a, 0x28] {
        let call = (0x30 - (arm + 5)) as u8;
        code[arm..arm + 6].copy_from_slice(&[0xe8, call, 0, 0, 0, 0xc3]);
    }
    let call = (ends - (BASE + 0x27)) as u32;
    code[0x20..0x22].copy_from_slice(&[0x31, 0xff]);
    code[0x22] = 0xe8;
    code[0x23..0x27].copy_from_slice(&call.to_le_bytes());
    code[0x30..0x38].copy_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x0f, 0x0b]);
    for (at, target) in [0x100e_u64, 0x1014, 0x101a, 0x1028].iter().enumerate() {
        code[0x40 + 8 * at..0x48 + 8 * at].copy_from_slice(&target.to_le_bytes());
    }
    code[0x90..0x96].copy_from_slice(&[0xff, 0x25, 0x02, 0x00, 0x00, 0x00]); // jmp [rip + 2]
    code[0x98..0xa0].fill(0);
    Box::leak(code.into_boxed_slice())
}

fn switch_rendered(ends: u64) -> String {
    let functions = [
        ("pick", BASE, 0x30),
        ("g", BASE + 0x30, 6),
        ("trap", BASE + 0x36, 2),
    ];
    let literal = Literal::of_code(switch_ending_at(ends), &functions)
        .importing("exit")
        .running_on(GLIBC);
    let mut open = OpenProgram::of(literal);
    let rendered = open.rendered(BASE).expect("it renders");
    rendered.response.output.into_text()
}

/// A switch arm ending at a call to `exit`, whose cited row states noreturn, names its exit: the
/// other arms' 32-bit `g()` is the whole result, with no undefined upper bytes (S23 D255, D211).
#[test]
fn a_switch_arm_that_calls_a_cited_noreturn_names_its_exit() {
    let text = switch_rendered(common::STUB);
    assert!(text.contains("r2sleigh_result_u32 pick("), "{text}");
    assert!(!text.contains("<< 32"), "{text}");
    assert!(!text.contains("unproven)"), "{text}");
}

/// The same arm ending at a body only the walk finds reaching no return names no exit: the "never"
/// is a bound, and the proof line counts the call as unproven (S23 D255; RULING 1.4).
#[test]
fn a_block_ended_at_an_unstated_call_names_no_exit() {
    let text = switch_rendered(BASE + 0x36);
    assert!(
        text.contains("1 call ends where no return was reached (unproven)"),
        "{text}"
    );
    assert!(text.contains("r2sleigh_result_u32 pick("), "{text}");
}
