//! A reference index says what it was read over.
//!
//! The index covers only the bodies discovery walked, so an address missing
//! from it is absent within that scope and nowhere else. The scope is part of
//! the answer: which functions were read, which could not be, and where a walk
//! stopped without knowing where control went.

mod common;

use std::sync::Arc;

use common::{BASE, CALLER, FORKED, JOINED, Literal, ONE, PASSES, SLOT, STEPPED, STUB, TEXT, TWO};
use r2engine::program::OpenProgram;
use r2engine::query::{AnnotationKind, Listing, Reference, Role, Stop, Support, Unread};
use r2ssa::body::{Unresolved, UnresolvedReason};

/// Every fact as `(from, to, role, support)`.
fn listed(facts: &[Reference]) -> Vec<(u64, u64, Role, Support)> {
    facts
        .iter()
        .map(|fact| (fact.from, fact.to, fact.role, fact.support))
        .collect()
}

#[test]
fn the_index_carries_the_scope_it_was_read_over() {
    let nowhere = BASE + 0x1000;
    let mut literal = Literal::new().stating("nowhere", nowhere);
    // two: jmp rax, whose target no walk can know
    literal.write(TWO, &[0xff, 0xe0]);
    let mut program = OpenProgram::of(literal);
    let answer = program.references().expect("the index builds");
    assert!(answer.is_complete());
    let index = answer.value;

    let coverage = &index.coverage;
    assert!(!coverage.is_closed());
    assert!(coverage.read.contains(&TWO), "{coverage:?}");
    assert!(!coverage.read.contains(&nowhere), "{coverage:?}");
    assert!(
        matches!(coverage.unread.get(&nowhere), Some(Unread::Refused(_))),
        "{coverage:?}"
    );
    assert_eq!(coverage.unread.len(), 1, "{coverage:?}");
    let stopped = Unresolved {
        addr: TWO,
        reason: UnresolvedReason::IndirectBranch,
    };
    assert_eq!(coverage.unresolved.get(&TWO), Some(&vec![stopped]));
    assert_eq!(coverage.unresolved.len(), 1, "{coverage:?}");
    assert_eq!(coverage.indirect_count(), 1);
}

#[test]
fn a_program_that_states_no_function_has_an_empty_index() {
    let mut program = OpenProgram::of(Literal::of_code(&[0xc3], &[]));
    let index = program.references().expect("the index builds").value;
    assert!(index.facts().is_empty(), "{:?}", index.facts());
    assert!(index.coverage.read.is_empty(), "{:?}", index.coverage);
}

#[test]
fn an_index_over_bodies_walked_to_their_end_is_closed() {
    let mut program = common::opened();
    let found = program.functions().expect("discovery runs").len();
    let index = program.references().expect("the index builds").value;
    assert!(index.coverage.is_closed(), "{:?}", index.coverage);
    assert_eq!(index.coverage.read.len(), found);
}

#[test]
fn each_reference_says_how_its_instruction_uses_the_address_and_what_shows_it() {
    // Linked at 0x1000, so a floor under which numbers are no addresses would
    // leave this empty. Every fact is a use, or a number that moves with the
    // program; `mov eax, 1` and the return address a call pushes are neither.
    let mut program = OpenProgram::of(Literal::new().importing("strlen"));
    let facts = program.references().expect("the index builds").value;
    use Support::{Certified, Decoded, Folded};
    assert_eq!(
        listed(facts.facts()),
        [
            // call one
            (CALLER, ONE, Role::Call, Decoded),
            // je L, in forked and in joined
            (FORKED + 9, FORKED + 0x10, Role::Jump, Decoded),
            (JOINED + 2, JOINED + 0xb, Role::Jump, Decoded),
            // lea rdi, [one], which the call after it takes as it stands; then call one
            (PASSES, ONE, Role::Value, Folded),
            (PASSES + 7, ONE, Role::Call, Decoded),
            // add rax, 8 after lea rax, [one]: the sum is the result, and only the def-use sees past the ret; the lea is a step
            (STEPPED + 7, ONE + 8, Role::Value, Certified),
            // jmp qword [rip + 2] reads the slot, and jumps to nothing the index can name
            (STUB, SLOT, Role::Read { width: 8 }, Decoded),
        ]
    );
}

/// `copies`: `lea rdi, [0x1020]; lea rsi, [0x1030]; mov ecx, 8; rep movsb; ret`.
const COPIES: u64 = BASE;
/// `calls`: `lea rax, [callee]; call rax; ret`.
const CALLS: u64 = BASE + 0x40;
/// `callee`: `mov eax, 1; ret`.
const CALLEE: u64 = BASE + 0x50;

const OPERATIONS: &[u8] = &{
    let mut code = [0xcc_u8; 0x60];
    let runs: [(usize, &[u8]); 3] = [
        (
            0x00,
            &[
                0x48, 0x8d, 0x3d, 0x19, 0, 0, 0, // lea rdi, [rip + 0x19]
                0x48, 0x8d, 0x35, 0x22, 0, 0, 0, // lea rsi, [rip + 0x22]
                0xb9, 8, 0, 0, 0, // mov ecx, 8
                0xf3, 0xa4, // rep movsb
                0xc3, // ret
            ],
        ),
        (
            0x40,
            &[
                0x48, 0x8d, 0x05, 0x09, 0, 0, 0, // lea rax, [rip + 9]
                0xff, 0xd0, // call rax
                0xc3, // ret
            ],
        ),
        (0x50, &[0xb8, 1, 0, 0, 0, 0xc3]),
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

#[test]
fn a_block_operation_and_a_computed_call_name_the_addresses_their_block_folds() {
    let literal = Literal::of_code(
        OPERATIONS,
        &[
            ("copies", COPIES, 0x16),
            ("calls", CALLS, 10),
            ("callee", CALLEE, 6),
        ],
    );
    let mut program = OpenProgram::of(literal);
    let index = program.references().expect("the index builds").value;
    let movsb = COPIES + 0x13;
    let byte = 1;
    assert_eq!(
        listed(index.facts()),
        [
            // rep movsb reads its first byte at rsi and writes it at rdi; rep movsb moves both, so neither lea is a result
            (
                movsb,
                BASE + 0x20,
                Role::Write { width: byte },
                Support::Folded
            ),
            (
                movsb,
                BASE + 0x30,
                Role::Read { width: byte },
                Support::Folded
            ),
            // lea rax, [callee], which the call takes as it stands; then call rax
            (CALLS, CALLEE, Role::Value, Support::Folded),
            (CALLS + 7, CALLEE, Role::Call, Support::Folded),
        ]
    );
    // The references to one address come back by source, each with the instruction and the function holding it.
    let to = index
        .to(CALLEE)
        .map(|(fact, source)| (fact.from, source.line.address, source.owners.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        to,
        [
            (CALLS, CALLS, vec![CALLS]),
            (CALLS + 7, CALLS + 7, vec![CALLS])
        ]
    );
    let text = index
        .to(CALLEE)
        .filter_map(|(_, source)| Some(source.line.syntax.as_ref()?.text()))
        .collect::<Vec<_>>();
    assert_eq!(text, ["lea rax, 0x1050", "call rax"]);
}

/// `left`: `test edi, edi; je tail; mov eax, 1; ret`; `tail`: `call leaf; ret`; `right`: `jmp tail`; `leaf`: `mov eax, 2; ret`.
const SHARED: &[u8] = &[
    0x85, 0xff, // 0x1000 test edi, edi
    0x74, 0x0c, // je 0x1010
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0xc3, // ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, //
    0xe8, 0x1b, 0x00, 0x00, 0x00, // 0x1010 call 0x1030
    0xc3, // ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, //
    0xeb, 0xee, // 0x1020 jmp 0x1010
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, //
    0xb8, 0x02, 0x00, 0x00, 0x00, // 0x1030 mov eax, 2
    0xc3, // ret
];

#[test]
fn a_tail_two_functions_share_is_held_by_each() {
    let (left, right, leaf) = (BASE, BASE + 0x20, BASE + 0x30);
    let literal = Literal::of_code(
        SHARED,
        &[("left", left, 10), ("right", right, 2), ("leaf", leaf, 6)],
    );
    let mut program = OpenProgram::of(literal);
    let index = program.references().expect("the index builds").value;
    let held = index
        .to(leaf)
        .map(|(fact, source)| (fact.from, fact.role, source.owners.clone()))
        .collect::<Vec<_>>();
    assert_eq!(held, [(BASE + 0x10, Role::Call, vec![left, right])]);
}

/// ARM `movw r3, #0x1020; movt r3, #0; mov lr, pc; bx r3; bx lr`, then at 0x1020 `mov r0, #1; bx lr`.
const LINKED: &[u8] = &[
    0x20, 0x30, 0x01, 0xe3, // movw r3, #0x1020
    0x00, 0x30, 0x40, 0xe3, // movt r3, #0
    0x0f, 0xe0, 0xa0, 0xe1, // mov lr, pc
    0x13, 0xff, 0x2f, 0xe1, // bx r3
    0x1e, 0xff, 0x2f, 0xe1, // bx lr
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x01, 0x00, 0xa0, 0xe3, // 0x1020 mov r0, #1
    0x1e, 0xff, 0x2f, 0xe1, // bx lr
];

#[test]
fn a_branch_that_leaves_its_return_address_in_the_link_register_is_a_call() {
    let callee = BASE + 0x20;
    let literal =
        Literal::of_code(LINKED, &[("linked", BASE, 0x14), ("callee", callee, 8)]).in_arm();
    let mut program = OpenProgram::of(literal);
    let index = program.references().expect("the index builds").value;
    // The lift spells `bx r3` after `mov lr, pc` as the call it is; the return address is a value the callee receives as it stands.
    assert_eq!(
        listed(index.facts()),
        [
            (BASE + 8, BASE + 0x10, Role::Value, Support::Folded),
            (BASE + 0xc, callee, Role::Call, Support::Folded),
        ]
    );
}

#[test]
fn the_index_is_read_once_per_state_of_the_program() {
    let mut program = common::opened();
    let first = program.references().expect("the index builds").value;
    let again = program.references().expect("the index builds").value;
    assert!(Arc::ptr_eq(&first, &again));
    // caller: call two; ret -- a write moves the state, so the index is read again and says so.
    let displacement = (TWO.wrapping_sub(CALLER + 5) as u32).to_le_bytes();
    let mut call = vec![0xe8];
    call.extend(displacement);
    program.source_mut().write(CALLER, &call);
    let after = program.references().expect("the index builds").value;
    assert!(!Arc::ptr_eq(&first, &after));
    let from_caller = |index: &r2engine::query::References| {
        index
            .facts()
            .iter()
            .filter(|fact| fact.from == CALLER)
            .map(|fact| (fact.to, fact.role))
            .collect::<Vec<_>>()
    };
    assert_eq!(from_caller(&first), [(ONE, Role::Call)]);
    assert_eq!(from_caller(&after), [(TWO, Role::Call)]);
}

#[test]
fn the_index_is_what_each_function_listing_claims() {
    // `ax` and `pdf` are one owner's answer: every fact from a function is a
    // claim a line of its listing makes, and every claim naming this program
    // is a fact. The ARM program switches instruction set inside one function.
    for literal in [
        Literal::new(),
        Literal::arm_thumb(),
        reading_callee(),
        declared_callee(),
    ] {
        let mut program = OpenProgram::of(literal);
        let index = program.references().expect("the index builds").value;
        let functions = program.functions().expect("discovery runs");
        let mut claimed = Vec::new();
        for function in &functions {
            let lines = program
                .function_listing(function.address)
                .expect("it lists")
                .value;
            claimed.extend(r2engine::query::references::claimed_by(&lines));
        }
        claimed.sort_unstable();
        claimed.dedup_by_key(|fact| (fact.from, fact.to, fact.role));
        assert_eq!(claimed, index.facts());
        assert!(!claimed.is_empty());
    }
}

/// `caller`: `mov edi, TEXT; call <callee>; ret`, handing an absolute number to its first parameter.
fn passing_text(literal: &mut Literal, callee: u64) {
    let after_call = CALLER + 10;
    let displacement = (callee.wrapping_sub(after_call) as u32).to_le_bytes();
    let text = (TEXT as u32).to_le_bytes();
    let mut bytes = vec![0xbf];
    bytes.extend(text);
    bytes.push(0xe8);
    bytes.extend(displacement);
    bytes.push(0xc3);
    literal.write(CALLER, &bytes);
}

/// `one` reads through its first parameter: `mov eax, [rdi]; ret`.
fn reading_callee() -> Literal {
    let mut literal = Literal::new().with_data();
    literal.write(ONE, &[0x8b, 0x07, 0xc3]);
    passing_text(&mut literal, ONE);
    literal
}

/// The call goes to the linkage stub of `strlen`, which is declared to take a pointer.
fn declared_callee() -> Literal {
    let mut literal = Literal::new().with_data().importing("strlen");
    passing_text(&mut literal, STUB);
    literal
}

/// What the `mov edi, TEXT` line claims about TEXT in `pd`, and the support `ax` holds it on.
fn claimed_at_caller(literal: Literal) -> (Option<Support>, Option<Support>) {
    let mut program = OpenProgram::of(literal);
    let listing = Listing {
        start: CALLER,
        stop: Stop::After(3),
    };
    let lines = program.listing(listing).expect("it lists").value;
    let support = lines[0]
        .annotations
        .iter()
        .find(|annotation| annotation.kind == AnnotationKind::Computes { value: TEXT })
        .map(|annotation| annotation.support);
    let index = program.references().expect("the index builds").value;
    let indexed = index
        .to(TEXT)
        .find(|(fact, _)| fact.from == CALLER && fact.role == Role::Value)
        .map(|(fact, _)| fact.support);
    (support, indexed)
}

#[test]
fn a_number_that_stays_put_is_an_address_only_where_a_callee_takes_one() {
    // The callee's own body loads through the parameter the number arrives in.
    let dereferenced = Some(Support::Dereferenced);
    assert_eq!(
        claimed_at_caller(reading_callee()),
        (dereferenced, dereferenced)
    );
    // A declaration types the parameter as a pointer.
    let declared = Some(Support::Declared);
    assert_eq!(claimed_at_caller(declared_callee()), (declared, declared));
    // `one` returns 1 and never reads its parameter, so the same number is only a number.
    let mut literal = Literal::new().with_data();
    passing_text(&mut literal, ONE);
    assert_eq!(claimed_at_caller(literal), (None, None));
    // Mapped but in no section the program loads, as NULL or the header would be, it names no object.
    let mut literal = Literal::new();
    literal.write(ONE, &[0x8b, 0x07, 0xc3]);
    passing_text(&mut literal, ONE);
    assert_eq!(claimed_at_caller(literal), (None, None));
}
