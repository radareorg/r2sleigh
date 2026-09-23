//! A reference index says what it was read over.
//!
//! The index covers only the bodies discovery walked, so an address missing
//! from it is absent within that scope and nowhere else. The scope is part of
//! the answer: which functions were read, which could not be, and where a walk
//! stopped without knowing where control went.

mod common;

use common::{BASE, FORKED, JOINED, Literal, ONE, TWO};
use r2engine::program::OpenProgram;
use r2engine::query::Unread;
use r2ssa::DataRefKind;
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
fn a_program_linked_low_still_has_references() {
    // Whether a constant is an address is what the program declares there,
    // not how large it is: this one is linked at 0x1000.
    let mut program = common::opened();
    let facts = program.references().expect("the index builds").value.facts;
    let named = |from: u64, kind: DataRefKind| {
        facts
            .iter()
            .any(|fact| fact.from == from && fact.to == ONE && fact.kind == kind)
    };
    assert!(named(FORKED, DataRefKind::Data), "{facts:?}");
    assert!(named(JOINED + 4, DataRefKind::Data), "{facts:?}");
    // And a small immediate names nothing the program declares.
    assert!(facts.iter().all(|fact| fact.to >= BASE), "{facts:?}");
}
