//! Whether a listed number is a result or a step, as `pd` and `pdf` each answer it,
//! and what a function listing says was proved.

mod common;

use common::{BASE, FORKED, JOINED, Literal, ONE, PASSES, SLOT, STEPPED, STUB, TWO, opened};
use r2engine::program::OpenProgram;
use r2engine::query::{AnnotationKind, Line, Listing, Stop, Support};

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

/// Each claim a line carries, with the rung it stands on.
fn supported(line: &Line) -> Vec<(AnnotationKind, Support)> {
    line.annotations
        .iter()
        .map(|annotation| (annotation.kind.clone(), annotation.support))
        .collect()
}

#[test]
fn each_claim_carries_the_smallest_evidence_that_establishes_it() {
    let rax = r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset: 0,
        size: 8,
    };
    // lea rax, [one]; add rax, 8; ret -- the ret ends the straight line, so only the def-use settles the sum.
    let stepped = opened().function_listing(STEPPED).expect("it lists").value;
    let sum = ONE + 8;
    assert_eq!(
        supported(&stepped[1]),
        [
            (AnnotationKind::Computes { value: sum }, Support::Certified),
            // The block folds the lea into the add, so the one value the range holds needs no more than the run.
            (
                AnnotationKind::Bounds {
                    storage: rax,
                    low: sum,
                    high: sum,
                    stride: 0,
                },
                Support::Folded,
            ),
        ]
    );
    // lea rdi, [one]; call one -- the call clobbers rdi, so the run after the lea settles it in either listing.
    let computes = [(AnnotationKind::Computes { value: ONE }, Support::Folded)];
    let plain = opened()
        .listing(Listing {
            start: PASSES,
            stop: Stop::After(3),
        })
        .expect("it lists");
    assert_eq!(supported(&plain.value[0]), computes);
    let whole = opened().function_listing(PASSES).expect("it lists").value;
    assert_eq!(supported(&whole[0]), computes);
    // mov eax, 1 fixes its value, and a number that stays put is no address, so the line claims nothing.
    let one = opened().function_listing(ONE).expect("it lists").value;
    assert_eq!(supported(&one[0]), []);
    // The lea's range would only restate the address its operand fixes, so FORKED's first line claims no range.
    let forked = opened().function_listing(FORKED).expect("it lists").value;
    assert!(bounds(&forked[..1]).is_empty(), "{:?}", forked[0]);
    // A constant copied in a later block is exact through the def-use, which the block's own run cannot see.
    let mut program = opened();
    program.source_mut().write(TWO, &CARRIED);
    let carried = program.function_listing(TWO).expect("it lists").value;
    let copy = carried.iter().find(|line| line.address == TWO + 0xa);
    let rcx = r2ssa::CanonicalStorageId { offset: 8, ..rax };
    let bound = AnnotationKind::Bounds {
        storage: rcx,
        low: 5,
        high: 5,
        stride: 0,
    };
    assert_eq!(copy.map(supported), Some(vec![(bound, Support::Certified)]));
}

/// `mov eax, 5; test edi, edi; je L; nop; L: mov ecx, eax; ret`
const CARRIED: [u8; 13] = [
    0xb8, 0x05, 0x00, 0x00, 0x00, 0x85, 0xff, 0x74, 0x01, 0x90, 0x89, 0xc1, 0xc3,
];

/// `one: mov eax, 1; ret`, `caller: lea rdi, [rip + 0x1e9]; call one; ret` and
/// `reader: mov rax, qword [rip + 0x1e9]; mov rcx, qword [rip + 0x1f2]; ret`,
/// with `"x"`, the word `0x402041` and `"hello world"` in the data after them.
const TEXTUAL: [u8; 0x400] = {
    let mut bytes = [0; 0x400];
    let runs: [(usize, &[u8]); 6] = [
        (0x00, &[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]),
        (
            0x10,
            &[
                0x48, 0x8d, 0x3d, 0xe9, 0x01, 0x00, 0x00, // lea rdi, [rip + 0x1e9]
                0xe8, 0xe4, 0xff, 0xff, 0xff, // call one
                0xc3, // ret
            ],
        ),
        (
            0x20,
            &[
                0x48, 0x8b, 0x05, 0xe9, 0x01, 0x00, 0x00, // mov rax, qword [rip + 0x1e9]
                0x48, 0x8b, 0x0d, 0xf2, 0x01, 0x00, 0x00, // mov rcx, qword [rip + 0x1f2]
                0xc3, // ret
            ],
        ),
        (0x200, b"x\0"),
        (0x210, &[0x41, 0x20, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]),
        (0x220, b"hello world\0"),
    ];
    let mut index = 0;
    while index < runs.len() {
        let (at, run) = runs[index];
        let mut offset = 0;
        while offset < run.len() {
            bytes[at + offset] = run[offset];
            offset += 1;
        }
        index += 1;
    }
    bytes
};

/// Where `TEXTUAL` keeps its one-character string.
const TEXT_AT: u64 = BASE + 0x200;

/// `TEXTUAL` opened, its code the first page and the rest a data section.
fn textual() -> OpenProgram<Literal> {
    let functions = [
        ("one", ONE, 6),
        ("caller", BASE + 0x10, 0xd),
        ("reader", BASE + 0x20, 0xf),
    ];
    OpenProgram::of(Literal::of_code(&TEXTUAL, &functions).with_data_after(BASE + 0x100))
}

#[test]
fn a_word_read_claims_only_the_text_that_runs_past_it() {
    let mut program = textual();
    let lines = program
        .listing(Listing {
            start: BASE + 0x20,
            stop: Stop::After(3),
        })
        .expect("it lists")
        .value;
    // The word is an address whose bytes spell `"A @"` then stop inside the read, so the read claims what it holds and no text.
    let (pointer, width) = (BASE + 0x210, 8);
    assert_eq!(
        supported(&lines[0]),
        [
            (
                AnnotationKind::Reads {
                    address: pointer,
                    width
                },
                Support::Decoded
            ),
            (
                AnnotationKind::Holds {
                    address: pointer,
                    width,
                    value: 0x40_2041,
                },
                Support::Decoded,
            ),
        ]
    );
    // Eight bytes of `"hello world"` are text running past the read, so the line says it.
    let hello = BASE + 0x220;
    let text = AnnotationKind::Text {
        address: hello,
        text: "hello world".to_owned(),
    };
    let said = supported(&lines[1]);
    assert!(said.contains(&(text, Support::Decoded)), "{said:?}");
}

#[test]
fn a_line_says_the_text_at_an_address_it_uses() {
    let caller = BASE + 0x10;
    let mut program = textual();
    let lines = program
        .listing(Listing {
            start: caller,
            stop: Stop::After(3),
        })
        .expect("it lists")
        .value;
    // The text is claimed on the rung of the claim that the line uses its address.
    let text = AnnotationKind::Text {
        address: TEXT_AT,
        text: "x".to_owned(),
    };
    assert_eq!(
        supported(&lines[0]),
        [
            (AnnotationKind::Computes { value: TEXT_AT }, Support::Folded),
            (text, Support::Folded),
        ]
    );
    // One character is text by chance too often to name it from a scan, so the name table has no string there.
    assert!(
        program.names().all_at(TEXT_AT).is_empty(),
        "{:?}",
        program.names().all_at(TEXT_AT)
    );
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
    // The mask is the and's own bound, which evaluating the instruction alone establishes.
    let masked = function.value.iter().find(|line| line.address == TWO + 2);
    let rung = masked
        .into_iter()
        .flat_map(|line| &line.annotations)
        .find(|annotation| matches!(annotation.kind, AnnotationKind::Bounds { .. }))
        .map(|annotation| annotation.support);
    assert_eq!(rung, Some(Support::Decoded));
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

#[test]
fn a_slot_the_loader_writes_is_read_but_never_said_to_hold_what_the_file_does() {
    // jmp qword [rip + 2] reads the slot the loader fills with the import, whatever the file's bytes there are.
    let mut program = OpenProgram::of(Literal::new().importing("_Exit"));
    let listing = Listing {
        start: STUB,
        stop: Stop::After(1),
    };
    let read = AnnotationKind::Reads {
        address: SLOT,
        width: 8,
    };
    let run = program.listing(listing).expect("it lists").value;
    assert_eq!(supported(&run[0]), [(read.clone(), Support::Decoded)]);
    let whole = program.function_listing(STUB).expect("it lists").value;
    assert_eq!(supported(&whole[0]), [(read, Support::Decoded)]);
}
