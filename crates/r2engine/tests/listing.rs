//! Whether a listed number is a result or a step, as `pd` and `pdf` each answer it,
//! and what a function listing says was proved.

mod common;

use common::{
    ARM_ENTRY, BASE, CALLER, FORKED, GUARDED_JOIN, HANDED, HANDS, JOINED, Literal, MOVED, ONE,
    OVERWRITTEN, PASSES, PLT_CALLER, PLT_STUB, SHIFT_MERGE, SLOT, STEPPED, STUB, THUMB_CALLED,
    THUMB_LEAF, TRANSFERRED, TWO, VENEER, handing, opened, table_switch, transferring,
};
use r2engine::program::{Container, OpenProgram, Source};
use r2engine::query::{AnnotationKind, ArgumentSlot, CallArgument, Line, Listing, Stop, Support};

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
    computes(
        &opened()
            .function_listing(entry)
            .expect("it lists")
            .lines
            .value,
    )
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
    // mov eax, 1; ret -- nothing reads it, but lifted a page on it is still 1, so it is no address.
    assert_eq!(pd(ONE, 2)[0], (ONE, None));
    assert_eq!(pdf(ONE)[0], (ONE, None));
    // lea rax, [one]; add rax, 8; ret -- the block carries the lea into the add, whose sum is returned.
    assert_eq!(pd(STEPPED, 3)[1], (STEPPED + 7, None));
    assert_eq!(pdf(STEPPED)[1], (STEPPED + 7, Some(ONE + 8)));
}

/// Every function these tests list, each in the program it is in.
fn listed_functions() -> Vec<(fn() -> Literal, u64)> {
    let common = [ONE, CALLER, TWO, FORKED, JOINED, PASSES, STEPPED];
    let common = common.map(|entry| (Literal::new as fn() -> Literal, entry));
    let own: [(fn() -> Literal, u64); 4] = [
        (
            || Literal::of_code(GUARDED_JOIN, &[("f", BASE, GUARDED_JOIN.len() as u64)]),
            BASE,
        ),
        (
            || Literal::of_code(SHIFT_MERGE, &[("f", BASE, SHIFT_MERGE.len() as u64)]),
            BASE,
        ),
        (|| Literal::of_code(OVERWRITTEN, &[("f", BASE, 0x10)]), BASE),
        (
            || Literal::of_code(MOVED, &[("f", BASE, 0x10)]).in_arm(),
            BASE,
        ),
    ];
    let arm = [ARM_ENTRY, THUMB_CALLED, THUMB_LEAF, VENEER]
        .map(|entry| (Literal::arm_thumb as fn() -> Literal, entry));
    let plt = [PLT_STUB, PLT_CALLER].map(|entry| (Literal::plt as fn() -> Literal, entry));
    let stub: (fn() -> Literal, u64) = (|| Literal::new().importing("_Exit"), STUB);
    common
        .into_iter()
        .chain(own)
        .chain(arm)
        .chain(plt)
        .chain([stub])
        .collect()
}

#[test]
fn every_claim_the_run_makes_the_function_listing_makes_on_the_same_line() {
    for (literal, entry) in listed_functions() {
        let mut program = OpenProgram::of(literal());
        let whole = program.function_listing(entry);
        let whole = whole
            .unwrap_or_else(|refused| panic!("{entry:#x} lists: {refused}"))
            .lines
            .value;
        let stop = Stop::After(whole.len());
        let run = program.listing(Listing { start: entry, stop });
        for line in &run.expect("it lists").value {
            let Some(function) = whole.iter().find(|one| one.address == line.address) else {
                continue;
            };
            // The rung may differ: what the run folds, the function may settle by its def-use.
            let claimed = function.annotations.iter().map(|one| &one.kind);
            let claimed = claimed.collect::<Vec<_>>();
            for annotation in &line.annotations {
                assert!(
                    claimed.contains(&&annotation.kind),
                    "{entry:#x}: pd claims {:?} at {:#x}, pdf {claimed:?}",
                    annotation.kind,
                    line.address
                );
            }
        }
    }
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
    let whole = program
        .function_listing(STUB)
        .expect("it lists")
        .lines
        .value;
    // The jump is a tail call through the slot, and nothing declares or proves what it hands on.
    let call = AnnotationKind::Call {
        callee: Some(SLOT),
        arguments: None,
        uncounted: None,
    };
    assert_eq!(
        supported(&whole[0]),
        [(read, Support::Decoded), (call, Support::Certified)]
    );
}

#[test]
fn a_function_listing_reads_through_an_address_until_a_byte_of_its_register_is_written() {
    let literal = Literal::of_code(OVERWRITTEN, &[("f", BASE, 0x10)]);
    let lines = OpenProgram::of(literal).function_listing(BASE);
    let lines = lines.expect("it lists").lines.value;
    let reads = |at: u64| {
        let line = lines.iter().find(|line| line.address == at);
        let annotations = line.into_iter().flat_map(|line| &line.annotations);
        let reads = annotations.filter_map(|annotation| match annotation.kind {
            AnnotationKind::Reads { address, width } => Some((address, width, annotation.support)),
            _ => None,
        });
        reads.collect::<Vec<_>>()
    };
    // `mov rcx, [rax]` reads the word the line before put in rax, which only the block's fold sees.
    assert_eq!(reads(BASE + 7), [(BASE + 0x10, 8, Support::Folded)]);
    // `mov al, 5` wrote a byte of rax, so the load after it names no address.
    assert_eq!(reads(BASE + 0xc), []);
}

#[test]
fn a_movw_and_movt_pair_is_one_address_the_load_after_them_reads() {
    let listed = |program: &mut OpenProgram<Literal>, whole: bool| {
        let lines = match whole {
            true => program.function_listing(BASE).map(|listing| listing.lines),
            false => program.listing(Listing {
                start: BASE,
                stop: Stop::After(4),
            }),
        };
        let lines = lines.expect("it lists").value;
        lines.iter().map(supported).collect::<Vec<_>>()
    };
    let mut program = OpenProgram::of(Literal::of_code(MOVED, &[("f", BASE, 0x10)]).in_arm());
    let (address, width) = (BASE + 0x10, 4);
    let read = [
        (AnnotationKind::Reads { address, width }, Support::Folded),
        (
            AnnotationKind::Holds {
                address,
                width,
                value: 0x0bad_f00d,
            },
            Support::Folded,
        ),
    ];
    // The block folds `movw` into `movt`, so the load reads the word the pair addresses.
    assert_eq!(listed(&mut program, true)[2], read);
    // Each line alone knows nothing of r0 at the load.
    assert_eq!(listed(&mut program, false)[2], []);
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
    let stepped = opened()
        .function_listing(STEPPED)
        .expect("it lists")
        .lines
        .value;
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
    let whole = opened()
        .function_listing(PASSES)
        .expect("it lists")
        .lines
        .value;
    assert_eq!(supported(&whole[0]), computes);
    // mov eax, 1 fixes its value, and a number that stays put is no address, so the line claims nothing.
    let one = opened()
        .function_listing(ONE)
        .expect("it lists")
        .lines
        .value;
    assert_eq!(supported(&one[0]), []);
    // The lea's range would only restate the address its operand fixes, so FORKED's first line claims no range.
    let forked = opened()
        .function_listing(FORKED)
        .expect("it lists")
        .lines
        .value;
    assert!(bounds(&forked[..1]).is_empty(), "{:?}", forked[0]);
    // A constant copied in a later block is exact through the def-use, which the block's own run cannot see.
    let mut program = opened();
    program.source_mut().write(TWO, &CARRIED);
    let carried = program.function_listing(TWO).expect("it lists").lines.value;
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

/// The address and text of every text claim a line makes.
fn texts(line: &Line) -> Vec<(u64, String)> {
    let texts = line
        .annotations
        .iter()
        .filter_map(|annotation| match &annotation.kind {
            AnnotationKind::Text { address, text } => Some((*address, text.clone())),
            _ => None,
        });
    texts.collect()
}

#[test]
fn a_transfer_target_holds_no_text_and_a_value_does() {
    let t = TRANSFERRED;
    let mut program = OpenProgram::of(transferring().with_data_after(t));
    let first = |program: &mut OpenProgram<Literal>, start: u64| {
        let listed = program.listing(Listing {
            start,
            stop: Stop::After(1),
        });
        listed.expect("it lists").value.remove(0)
    };
    // `call t` and `jmp t` execute the bytes at t, so the `"1"` they spell is no string there.
    for (at, call) in [(BASE, true), (BASE + 0x10, false)] {
        let line = first(&mut program, at);
        let target = AnnotationKind::Target { address: t, call };
        assert!(
            line.annotations.iter().any(|one| one.kind == target),
            "{line:?}"
        );
        assert_eq!(texts(&line), [], "{line:?}");
    }
    // `lea rdi, [t]` computes the address as a value, so the text there is said beside it.
    let lea = first(&mut program, BASE + 0x20);
    let computes = AnnotationKind::Computes { value: t };
    assert!(
        lea.annotations.iter().any(|one| one.kind == computes),
        "{lea:?}"
    );
    assert_eq!(texts(&lea), [(t, "1".to_owned())]);
    // The function listing reads the same rule: the call line names t and no text.
    let whole = program
        .function_listing(BASE)
        .expect("it lists")
        .lines
        .value;
    let call = whole.iter().find(|line| line.address == BASE);
    let call = call.expect("the call is listed");
    let target = AnnotationKind::Target {
        address: t,
        call: true,
    };
    assert!(
        call.annotations.iter().any(|one| one.kind == target),
        "{call:?}"
    );
    assert_eq!(texts(call), [], "{call:?}");
    // Where the container states the bytes hold instructions, no use of them reads a string.
    let mut stated = OpenProgram::of(transferring().with_code_after(t));
    let lea = first(&mut stated, BASE + 0x20);
    assert!(
        lea.annotations.iter().any(|one| one.kind == computes),
        "{lea:?}"
    );
    assert_eq!(texts(&lea), [], "{lea:?}");
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
    let function = program.function_listing(TWO).expect("it lists").lines;
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

/// What the certificates anchor at each line, by address, in the order the line lists them.
fn certified(lines: &[Line]) -> Vec<(u64, AnnotationKind, Support)> {
    let certified = |kind: &AnnotationKind| {
        matches!(
            kind,
            AnnotationKind::Call { .. }
                | AnnotationKind::ArgumentOf { .. }
                | AnnotationKind::Switch { .. }
                | AnnotationKind::Case { .. }
                | AnnotationKind::Default { .. }
                | AnnotationKind::Unresolved
                | AnnotationKind::Loop { .. }
                | AnnotationKind::Induction { .. }
                | AnnotationKind::Trips(_)
                | AnnotationKind::Returns { .. }
        )
    };
    let on = |line: &Line| {
        let claims = line.annotations.iter().filter(|one| certified(&one.kind));
        let at = line.address;
        let claims = claims.map(move |one| (at, one.kind.clone(), one.support));
        claims.collect::<Vec<_>>()
    };
    lines.iter().flat_map(on).collect()
}

fn register(offset: u64) -> r2ssa::CanonicalStorageId {
    r2ssa::CanonicalStorageId {
        space: r2ssa::CanonicalStorageSpace::Register,
        offset,
        size: 8,
    }
}

#[test]
fn a_call_line_says_what_its_boundary_hands_on_and_the_line_that_set_it_says_so() {
    let (rax, rdi) = (register(0), register(0x38));
    let mut program = OpenProgram::of(handing());
    let hands = program
        .function_listing(HANDS)
        .expect("it lists")
        .lines
        .value;
    let call = HANDS + 7;
    let argument = CallArgument {
        index: 0,
        slot: ArgumentSlot::Register(rdi),
        value: Some(HANDED),
    };
    let returns = AnnotationKind::Returns { storage: rax };
    assert_eq!(
        certified(&hands),
        [
            // The lea's own lift folds the address, so the def-use certifies the one value the call is handed.
            (
                HANDS,
                AnnotationKind::ArgumentOf { call, index: 0 },
                Support::Certified
            ),
            (
                call,
                AnnotationKind::Call {
                    callee: Some(BASE),
                    arguments: Some(vec![argument]),
                    uncounted: None,
                },
                Support::Certified,
            ),
            (call + 5, returns.clone(), Support::Certified),
        ]
    );
    let ident = program
        .function_listing(BASE)
        .expect("it lists")
        .lines
        .value;
    assert_eq!(certified(&ident), [(BASE + 3, returns, Support::Certified)]);
}

#[test]
fn a_dispatch_says_where_its_table_is_and_each_arm_which_cases_reach_it() {
    let lines = OpenProgram::of(table_switch()).function_listing(BASE);
    let lines = lines.expect("it lists").lines.value;
    let dispatch = BASE + 7;
    let arms = [(0, 0x100e), (1, 0x1014), (2, 0x101a), (3, 0x1026)];
    // The table lies in the code, which nothing writes once the program runs.
    let table = r2engine::native::DispatchTable {
        address: BASE + 0x30,
        entry_size: 8,
        entries: 4,
        stated: r2engine::native::TableBytes::ReadOnly,
    };
    let case = |value: u64| AnnotationKind::Case {
        values: vec![value],
        dispatch,
    };
    // The guard's `ja` sends every index past three to the default, and only its other edge reaches the dispatch.
    let default = AnnotationKind::Default {
        dispatch,
        guard: BASE + 3,
    };
    let switch = AnnotationKind::Switch {
        arms: arms.to_vec(),
        default: Some(BASE + 0x20),
        table: Some(table),
    };
    let said = certified(&lines);
    let switched = |at: u64, kind: AnnotationKind| (at, kind, Support::Solved);
    for expected in [
        switched(dispatch, switch),
        switched(0x100e, case(0)),
        switched(0x1014, case(1)),
        switched(0x101a, case(2)),
        switched(0x1026, case(3)),
        switched(0x1020, default),
    ] {
        assert!(said.contains(&expected), "{expected:?} not in {said:?}");
    }
    // A dispatch whose table the walk read is no unresolved branch.
    let unresolved = said
        .iter()
        .any(|(_, kind, _)| *kind == AnnotationKind::Unresolved);
    assert!(!unresolved, "{said:?}");
}

#[test]
fn a_table_the_program_may_write_is_read_as_the_file_holds_it_and_says_so() {
    // Nothing the container states is yet asked whether it seals a writable
    // table after load -- a RELRO range, a read-only segment -- so the table
    // is read as the file holds it, and it carries that it was unsealed for
    // the check that asks to consume rather than recompute.
    let program = table_switch().writable_data_after(BASE + 0x30);
    let lines = OpenProgram::of(program).function_listing(BASE);
    let lines = lines.expect("it lists").lines.value;
    let tables = lines
        .iter()
        .flat_map(|line| &line.annotations)
        .filter_map(|annotation| match &annotation.kind {
            AnnotationKind::Switch { table, .. } => *table,
            _ => None,
        })
        .map(|table| (table.address, table.entries, table.stated))
        .collect::<Vec<_>>();
    let unsealed = r2engine::native::TableBytes::Unsealed;
    assert_eq!(tables, [(BASE + 0x30, 4, unsealed)]);
}

#[test]
fn a_function_whose_analysis_is_refused_is_still_listed_and_says_why() {
    // `pdf` used to begin by preparing the function, so a refusal -- or a
    // panic, or running out of memory -- took the disassembly with it. The
    // bytes never depend on the analysis: the plain walk is listed, and the
    // dispatch it could not follow is named rather than guessed at.
    let mut program = OpenProgram::of(table_switch());
    let cancellation = r2engine::EngineCancellationToken::default();
    program.begin_request(r2engine::EngineExecutionControl::with_cancellation(
        cancellation.clone(),
    ));
    cancellation.cancel();
    let listing = program
        .function_listing(BASE)
        .expect("the refusal is the analysis's, not the listing's");
    let listed = |lines: &[Line]| lines.iter().map(|line| line.address).collect::<Vec<_>>();
    let refused = listing.refused.expect("it says the analysis was refused");
    assert!(
        matches!(refused.reason, r2engine::native::NativeRefusal::Prepare(_)),
        "{:?}",
        refused.reason
    );
    let dispatch = BASE + 7;
    assert_eq!(refused.unresolved, vec![dispatch]);
    // The guard, the dispatch and the default the guard reaches, its move and
    // its return; no arm, since reading the table is the analysis's.
    assert_eq!(
        listed(&listing.lines.value),
        vec![BASE, BASE + 3, BASE + 5, dispatch, BASE + 0x20, BASE + 0x25]
    );
    // Asked again with nothing stopping it, the arms are there and nothing is refused.
    let analysed = program.function_listing(BASE).expect("it lists");
    assert!(analysed.refused.is_none());
    assert!(listed(&analysed.lines.value).contains(&0x100e));
}

/// The literal program, with one address whose bytes cannot be read without a defect.
struct Faulting {
    literal: Literal,
    at: u64,
}

impl Source for Faulting {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        assert_ne!(vaddr, self.at, "a defect reading {vaddr:#x}");
        self.literal.read(vaddr, max)
    }

    fn container(&self) -> &Container {
        self.literal.container()
    }

    fn identity(&self) -> u64 {
        self.literal.identity()
    }

    fn byte_revision(&self) -> u64 {
        self.literal.byte_revision()
    }

    fn written_since(&self, revision: u64, range: &std::ops::Range<u64>) -> bool {
        self.literal.written_since(revision, range)
    }
}

#[test]
fn a_walk_that_panics_is_the_listings_refusal_and_the_session_goes_on() {
    // The analysis was isolated, and the listing it fell back to walked the
    // body again outside any boundary: the same defect in the walk then
    // unwound through the caller, and a shell ended with it. Where not even
    // the plain walk can be read, nothing is listed and the error says where
    // the defect was raised.
    let ret = TWO + 5;
    let mut program = OpenProgram::of(Faulting {
        literal: Literal::new(),
        at: ret,
    });
    let refused = match program.function_listing(TWO) {
        Ok(listing) => panic!(
            "a body read through a defect is listed: {:?}",
            computes(&listing.lines.value)
        ),
        Err(refused) => refused,
    };
    assert!(refused.contains("the plain walk panicked at "), "{refused}");
    assert!(refused.contains("listing.rs"), "{refused}");
    let defect = format!("a defect reading {ret:#x}");
    assert!(refused.contains(&defect), "{refused}");
    // The same defect refused the analysis first, and that is said too.
    assert!(refused.contains("the analysis panicked at "), "{refused}");
    // The next function is untouched by it.
    let one = program.function_listing(ONE).expect("the session goes on");
    assert!(one.refused.is_none());
    assert_eq!(one.lines.value.first().map(|line| line.address), Some(ONE));
}
