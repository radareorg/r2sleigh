//! What `pdf` says a value lies in holds on every path that defines it.

mod common;

use common::{BASE, GUARDED_JOIN, Literal, SHIFT_MERGE};
use r2engine::program::OpenProgram;
use r2engine::query::AnnotationKind;

/// Each range `pdf` proves on the line at `address`.
fn proved_at(code: &'static [u8], address: u64) -> Vec<(u64, u64, u64)> {
    let literal = Literal::of_code(code, &[("f", BASE, code.len() as u64)]);
    let lines = OpenProgram::of(literal)
        .function_listing(BASE)
        .expect("it lists")
        .value;
    lines
        .iter()
        .filter(|line| line.address == address)
        .flat_map(|line| &line.annotations)
        .filter_map(|annotation| match annotation.kind {
            AnnotationKind::Bounds {
                low, high, stride, ..
            } => Some((low, high, stride)),
            _ => None,
        })
        .collect()
}

#[test]
fn a_branch_into_a_merge_bounds_nothing_there() {
    // The fall-through path reaches L with rdi below ten, so `jae` proves nothing about L.
    let proved = proved_at(GUARDED_JOIN, BASE + 0xb);
    assert!(proved.iter().all(|(low, _, _)| *low == 0), "{proved:?}");
}

#[test]
fn a_shift_keeps_every_value_its_carries_reach() {
    let proved = proved_at(SHIFT_MERGE, BASE + 0x1d);
    let holds = |value: u64| {
        proved.iter().any(|(low, high, stride)| {
            r2ssa::StridedInterval::strided(64, *stride, *low, *high).contains(value)
        })
    };
    assert!(!proved.is_empty(), "the shift is bounded");
    assert!(holds(5) && holds(2) && holds(0), "{proved:?}");
}
