//! An indirect call through a table the container states, with an index the value analysis bounds
//! (ROADMAP P5): it states its target set, and anything less certain states none.

use crate::common::{BASE, Literal};
use r2engine::discovery::Basis;
use r2engine::program::OpenProgram;
use r2engine::query::{AnnotationKind, Line};

/// Where the table lies in `guarded`, and the call that reads it.
const TABLE: u64 = BASE + 0x30;
const CALL: u64 = BASE + 7;
const CALLEES: [u64; 3] = [BASE + 0x12, BASE + 0x18, BASE + 0x1e];

/// `cmp edi|esi, bound; ja out; mov edi, edi; call [rdi*8 + 0x1030]; ret`, then three callees at
/// 0x1012 and the table of `entries` at `TABLE`.
fn guarded(bound: u8, guard_reg_esi: bool, entries: &[u64]) -> Vec<u8> {
    let mut code = vec![
        0x83,
        if guard_reg_esi { 0xfe } else { 0xff },
        bound,
        0x77,
        0x0a,
        0x89,
        0xff,
        0xff,
        0x14,
        0xfd,
        0x30,
        0x10,
        0x00,
        0x00,
        0xc3,
        0x31,
        0xc0,
        0xc3,
    ];
    for value in [10u8, 20, 30] {
        code.extend_from_slice(&[0xb8, value, 0, 0, 0, 0xc3]);
    }
    code.resize(0x30, 0);
    for entry in entries {
        code.extend_from_slice(&entry.to_le_bytes());
    }
    code
}

fn leaked(code: Vec<u8>) -> &'static [u8] {
    Box::leak(code.into_boxed_slice())
}

/// The program as one function, `dispatch`, with its table in read-only data.
fn program(code: Vec<u8>) -> Literal {
    let code = leaked(code);
    Literal::of_code(code, &[("dispatch", BASE, 0x12)]).data_mapped_after(TABLE)
}

/// Every function the line at `at` is annotated as calling, with the rung that says so.
fn called(lines: &[Line], at: u64) -> Vec<(u64, Basis)> {
    (lines.iter().filter(|line| line.address == at))
        .flat_map(|line| &line.annotations)
        .filter_map(|annotation| match annotation.kind {
            AnnotationKind::Target {
                address,
                call: true,
            } => Some((address, annotation.support)),
            _ => None,
        })
        .collect()
}

fn listed(literal: Literal) -> Vec<Line> {
    let mut program = OpenProgram::of(literal);
    program
        .function_listing(BASE)
        .expect("it lists")
        .lines
        .value
}

#[test]
fn a_call_through_a_guarded_read_only_table_states_its_targets() {
    let lines = listed(program(guarded(2, false, &CALLEES)));
    let targets = CALLEES.map(|target| (target, Basis::Solved));
    assert_eq!(called(&lines, CALL), targets);
}

#[test]
fn the_rendering_names_the_set_and_claims_no_callee() {
    let mut open = OpenProgram::of(program(guarded(2, false, &CALLEES)));
    let c = open
        .rendered(BASE)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(c.contains("call to one of 0x1012, 0x1018, 0x101e"), "{c}");
    assert!(!c.contains("0x1012()"), "{c}");
}

#[test]
fn a_table_the_program_may_write_states_no_targets() {
    let code = leaked(guarded(2, false, &CALLEES));
    let literal = Literal::of_code(code, &[("dispatch", BASE, 0x12)]).writable_data_after(TABLE);
    assert_eq!(called(&listed(literal), CALL), []);
}

#[test]
fn an_index_the_guard_does_not_bound_states_no_targets() {
    // The guard tests esi; the table is indexed by edi, which reaches 2^32 entries.
    let lines = listed(program(guarded(2, true, &CALLEES)));
    assert_eq!(called(&lines, CALL), []);
}

#[test]
fn an_index_one_past_the_table_states_no_targets() {
    // Four entries are selected and the table holds three, then ends the region.
    let lines = listed(program(guarded(3, false, &CALLEES)));
    assert_eq!(called(&lines, CALL), []);
    // The fourth entry is read-only data that is no instruction.
    let mut entries = CALLEES.to_vec();
    entries.push(0);
    let lines = listed(program(guarded(3, false, &entries)));
    assert_eq!(called(&lines, CALL), []);
}

#[test]
fn an_entry_that_is_no_code_states_no_targets() {
    // Entry 1 points into the table itself, which no instruction can run from.
    let entries = [CALLEES[0], TABLE, CALLEES[2]];
    let lines = listed(program(guarded(2, false, &entries)));
    assert_eq!(called(&lines, CALL), []);
}

/// clang -O1's `table_dispatch` on AArch64: `x20` counts 0 to 2 and `blr x8` calls `[x21 + x20 * 8]`.
/// The callees (`add`, `eor` and `mul` over `x0`, `x1`) begin at `BASE + 0x48`, the table at `BASE + 0x60`.
fn loop_code() -> Vec<u8> {
    let words: [u32; 30] = [
        0xa9bd7bfd, 0xf9000bf5, 0xa9024ff4, 0x910003fd, 0xaa0103f3, 0xaa1f03f4, 0x10000255,
        0xf8747aa8, 0x8b140261, 0xd63f0100, 0x91000694, 0xf1000e9f, 0x54ffff61, 0xa9424ff4,
        0xf9400bf5, 0xa8c37bfd, 0xd65f03c0, 0xd503201f, 0x8b010000, 0xd65f03c0, 0xca010000,
        0xd65f03c0, 0x9b017c00, 0xd65f03c0, 0x1048, 0, 0x1050, 0, 0x1058, 0,
    ];
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

#[test]
fn a_call_in_a_counted_loop_states_the_table_entries_the_counter_selects() {
    let code = leaked(loop_code());
    let literal = Literal::of_code(code, &[("dispatch", BASE, 0x48)])
        .in_aarch64()
        .data_mapped_after(BASE + 0x60);
    let targets = [BASE + 0x48, BASE + 0x50, BASE + 0x58].map(|target| (target, Basis::Solved));
    assert_eq!(called(&listed(literal), BASE + 0x24), targets);
}

#[test]
fn a_loop_counted_past_the_table_states_no_targets() {
    // `cmp x20, #4` runs the loop four times over a table of three entries.
    let mut words = loop_code();
    words[0x2c..0x30].copy_from_slice(&0xf100129fu32.to_le_bytes());
    let code = leaked(words);
    let literal = Literal::of_code(code, &[("dispatch", BASE, 0x48)])
        .in_aarch64()
        .data_mapped_after(BASE + 0x60);
    assert_eq!(called(&listed(literal), BASE + 0x24), []);
}
