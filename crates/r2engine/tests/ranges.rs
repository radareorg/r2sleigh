//! What `pdf` says a value lies in holds on every path that defines it.

mod common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;
use r2engine::query::AnnotationKind;

/// `cmp rdi, 10; jae L; mov esi, 0; L: mov rax, rdi; ret`: L is entered with rdi below ten and above.
const GUARDED_JOIN: &[u8] = &[
    0x48, 0x83, 0xff, 0x0a, // cmp rdi, 10
    0x73, 0x05, // jae L
    0xbe, 0x00, 0x00, 0x00, 0x00, // mov esi, 0
    0x48, 0x89, 0xf8, // L: mov rax, rdi
    0xc3, // ret
];

/// `eax` is one, eleven or twenty-one where `shr eax, 2` reads it, so the shift leaves nought, two or five.
const SHIFT_MERGE: &[u8] = &[
    0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0x83, 0xff, 0x01, // cmp edi, 1
    0x74, 0x07, // je 0x1011
    0x83, 0xff, 0x02, // cmp edi, 2
    0x74, 0x09, // je 0x1018
    0xeb, 0x0c, // jmp 0x101d
    0xb8, 0x0b, 0x00, 0x00, 0x00, // 0x1011 mov eax, 11
    0xeb, 0x05, // jmp 0x101d
    0xb8, 0x15, 0x00, 0x00, 0x00, // 0x1018 mov eax, 21
    0xc1, 0xe8, 0x02, // 0x101d shr eax, 2
    0xc3, // ret
];

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
