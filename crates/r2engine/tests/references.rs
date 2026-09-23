//! A reference index says what it was read over.
//!
//! The index covers only the bodies discovery walked, so an address missing
//! from it is absent within that scope and nowhere else. The scope is part of
//! the answer: which functions were read, which could not be, and where a walk
//! stopped without knowing where control went.

mod common;

use common::{BASE, CALLER, FORKED, JOINED, Literal, ONE, PASSES, STEPPED, TWO};
use r2engine::program::OpenProgram;
use r2engine::query::{ReferenceKind, Unread};
use r2ssa::body::{Unresolved, UnresolvedReason};

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
fn an_index_over_bodies_walked_to_their_end_is_closed() {
    let mut program = common::opened();
    let found = program.functions().expect("discovery runs").len();
    let index = program.references().expect("the index builds").value;
    assert!(index.coverage.is_closed(), "{:?}", index.coverage);
    assert_eq!(index.coverage.read.len(), found);
}

#[test]
fn a_program_linked_low_has_exactly_the_references_its_listing_claims() {
    // Linked at 0x1000, so a floor under which numbers are no addresses would
    // leave this empty. Every fact is a use, or a number that moves with the
    // program; `mov eax, 1` and the return address a call pushes are neither.
    let mut program = common::opened();
    let facts = program.references().expect("the index builds").value.facts;
    let (code, data) = (ReferenceKind::Code, ReferenceKind::Data);
    let listed = facts
        .iter()
        .map(|fact| (fact.from, fact.to, fact.kind))
        .collect::<Vec<_>>();
    assert_eq!(
        listed,
        [
            // call one
            (CALLER, ONE, code),
            // je L, in forked and in joined
            (FORKED + 9, FORKED + 0x10, code),
            (JOINED + 2, JOINED + 0xb, code),
            // lea rdi, [one], passed as it stands; then call one
            (PASSES, ONE, data),
            (PASSES + 7, ONE, code),
            // add rax, 8 after lea rax, [one], in one block: the sum is what is returned
            (STEPPED + 7, ONE + 8, data),
        ]
    );
}

#[test]
fn the_index_is_what_each_function_listing_claims() {
    // `ax` and `pdf` are one owner's answer: every fact from a function is a
    // claim a line of its listing makes, and every claim naming this program
    // is a fact. The ARM program switches instruction set inside one function.
    for literal in [Literal::new(), Literal::arm_thumb()] {
        let mut program = OpenProgram::of(literal);
        let facts = program.references().expect("the index builds").value.facts;
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
        claimed.dedup();
        assert_eq!(claimed, facts);
        assert!(!facts.is_empty());
    }
}
