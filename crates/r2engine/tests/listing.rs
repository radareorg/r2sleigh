//! Whether a listed number is a result or a step, as `pd` and `pdf` each answer it,
//! and what a function listing says was proved.

mod common;

use common::{FORKED, JOINED, ONE, PASSES, STEPPED, TWO, opened};
use r2engine::query::{AnnotationKind, Line, Listing, Stop};

/// The result each line claims, by address.
fn computes(lines: &[Line]) -> Vec<(u64, Option<u64>)> {
    lines
        .iter()
        .map(|line| {
            let value = line
                .annotations
                .iter()
                .find_map(|annotation| match annotation.kind {
                    AnnotationKind::Computes { value } => Some(value),
                    _ => None,
                });
            (line.address, value)
        })
        .collect()
}

fn pd(entry: u64, count: usize) -> Vec<(u64, Option<u64>)> {
    let answer = opened()
        .listing(Listing {
            start: entry,
            stop: Stop::After(count),
        })
        .expect("it lists");
    computes(&answer.value)
}

fn pdf(entry: u64) -> Vec<(u64, Option<u64>)> {
    computes(&opened().function_listing(entry).expect("it lists").value)
}

#[test]
fn an_address_built_on_past_a_branch_is_not_claimed_a_result() {
    // The overwrite is skipped on the taken path, and the add at L builds on the address.
    assert_eq!(pd(FORKED, 6)[0], (FORKED, None));
    assert_eq!(pdf(FORKED)[0], (FORKED, None));
}

#[test]
fn the_function_listing_refines_the_run_and_never_contradicts_it() {
    // lea rax, [one] falls through into L, which the branch also enters, and L adds to it.
    let lea = JOINED + 4;
    assert_eq!(pd(JOINED, 5)[2], (lea, None));
    assert_eq!(pdf(JOINED)[2], (lea, None));
    // Every result the run claims, the function claims too.
    for entry in [FORKED, JOINED, ONE, PASSES, STEPPED] {
        let whole = pdf(entry);
        for (address, claimed) in pd(entry, whole.len()) {
            if claimed.is_some() {
                assert!(whole.contains(&(address, claimed)), "{address:#x}");
            }
        }
    }
    // mov eax, 1; ret -- nothing reads it, but lifted a page on it is still 1, so it is no address.
    assert_eq!(pd(ONE, 2)[0], (ONE, None));
    assert_eq!(pdf(ONE)[0], (ONE, None));
    // lea rax, [one]; add rax, 8; ret -- the block carries the lea into the add, whose sum is returned.
    assert_eq!(pd(STEPPED, 3)[1], (STEPPED + 7, None));
    assert_eq!(pdf(STEPPED)[1], (STEPPED + 7, Some(ONE + 8)));
}

#[test]
fn an_address_passed_to_a_call_is_a_result() {
    // lea rdi, [one]; call one -- the callee is handed the address, and the call leaves rdi undefined.
    assert_eq!(pd(PASSES, 3)[0], (PASSES, Some(ONE)));
    assert_eq!(pdf(PASSES)[0], (PASSES, Some(ONE)));
}

#[test]
fn an_address_the_next_instruction_adds_to_is_a_step() {
    assert_eq!(pd(STEPPED, 3)[0], (STEPPED, None));
    assert_eq!(pdf(STEPPED)[0], (STEPPED, None));
}

#[test]
fn a_value_the_prelude_mints_leaves_every_line_its_own_definitions() {
    // The entry block reads `edi`, so a projection is minted ahead of the lea without taking its place.
    let rax = |kind: &AnnotationKind| match kind {
        AnnotationKind::Bounds {
            storage, low, high, ..
        } => (storage.offset == 0 && storage.size == 8).then_some((*low, *high)),
        _ => None,
    };
    let lines = opened().function_listing(FORKED).expect("it lists").value;
    let proved = |address: u64| {
        let line = lines.iter().find(|line| line.address == address);
        line.into_iter()
            .flat_map(|line| &line.annotations)
            .filter_map(|annotation| rax(&annotation.kind))
            .collect::<Vec<_>>()
    };
    assert_eq!(proved(FORKED), [(ONE, ONE)]);
    assert_eq!(proved(FORKED + 7), []);
}

/// `mov eax, edi; and eax, 7; ret`
const MASKED: [u8; 8] = [0x89, 0xf8, 0x83, 0xe0, 0x07, 0xc3, 0xcc, 0xcc];

/// Each proved range, with the line it is on.
fn bounds(lines: &[Line]) -> Vec<(u64, u64, u64)> {
    lines
        .iter()
        .flat_map(|line| line.annotations.iter().map(move |one| (line.address, one)))
        .filter_map(|(at, annotation)| match annotation.kind {
            AnnotationKind::Bounds { low, high, .. } => Some((at, low, high)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_function_listing_says_what_was_proved_about_each_value() {
    let mut program = opened();
    program.source_mut().write(TWO, &MASKED);
    let function = program.function_listing(TWO).expect("it lists");
    let proved = bounds(&function.value);
    assert!(proved.contains(&(TWO + 2, 0, 7)), "{proved:?}");
    // Writing eax only restates the width a 32-bit write clears, which says nothing.
    assert!(!proved.contains(&(TWO, 0, 0xffff_ffff)), "{proved:?}");
    let plain = program
        .listing(Listing {
            start: TWO,
            stop: Stop::After(3),
        })
        .expect("it lists");
    assert!(bounds(&plain.value).is_empty(), "{:?}", plain.value);
}
