//! What the structurer writes for a function, from its bytes and an address.

use crate::common;

use std::collections::BTreeSet;

use common::{BASE, Literal};
use r2dec::placement_mutants::{WriteOrder, with_write_order};
use r2engine::program::OpenProgram;

fn c_of(code: &'static [u8]) -> String {
    let size = code.len() as u64;
    let mut program = OpenProgram::of(Literal::of_code(code, &[("f", BASE, size)]));
    program
        .rendered(BASE)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// The `if` lines of a rendering.
fn tests_of(c: &str) -> Vec<&str> {
    c.lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("if "))
        .collect()
}

/// `test edi, edi; jne no; test esi, esi; jne no; mov eax, 1; ret; no: xor eax, eax; ret`
const BOTH_ZERO: &[u8] = &[
    0x85, 0xff, 0x75, 0x0a, 0x85, 0xf6, 0x75, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31, 0xc0,
    0xc3,
];

/// `test edi, edi; jne yes; test esi, esi; je no; yes: mov eax, 1; ret; no: xor eax, eax; ret`
const EITHER_NOT_ZERO: &[u8] = &[
    0x85, 0xff, 0x75, 0x04, 0x85, 0xf6, 0x74, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31, 0xc0,
    0xc3,
];

/// `test edi, edi; jne no; cmp dword [rsi], 0; jne no; mov eax, 1; ret; no: xor eax, eax; ret`
const SECOND_TEST_LOADS: &[u8] = &[
    0x85, 0xff, 0x75, 0x0b, 0x83, 0x3e, 0x00, 0x75, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31,
    0xc0, 0xc3,
];

#[test]
fn two_tests_that_fail_to_one_exit_are_one_conjunction() {
    let c = c_of(BOTH_ZERO);
    let tests = tests_of(&c);
    assert_eq!(tests.len(), 1, "{c}");
    // The text is the machine's: both zero, which is what the source says.
    assert_eq!(tests[0].matches("== (uint32_t)0U").count(), 2, "{c}");
    assert!(tests[0].contains(" && ") && !tests[0].contains('!'), "{c}");
    assert!(!c.contains("goto"), "{c}");
}

#[test]
fn the_exit_only_the_chain_reaches_is_the_if_s_body() {
    // Either input non-zero returns 1, which both tests reach; zero for both returns 0, which only
    // the second test does, so that block is the body and the first block is the jump.
    let c = c_of(EITHER_NOT_ZERO);
    let tests = tests_of(&c);
    assert_eq!(tests.len(), 1, "{c}");
    assert_eq!(tests[0].matches("== (uint32_t)0U").count(), 2, "{c}");
    assert!(tests[0].contains(" && "), "{c}");
    assert!(c.contains("return 0;"), "{c}");
}

#[test]
fn a_second_test_that_reads_memory_is_a_test_of_its_own() {
    // The load is a statement between the two tests, so the second block is no part of the first's.
    let c = c_of(SECOND_TEST_LOADS);
    assert_eq!(tests_of(&c).len(), 2, "{c}");
    assert!(!c.contains(" && ") && !c.contains(" || "), "{c}");
}

/// `test edi, edi; jne no; sub esi, 5; jne no; mov eax, esi; ret; no: xor eax, eax; ret`: the second
/// test's block also computes the value the function returns.
const SECOND_TEST_KEEPS_ITS_VALUE: &[u8] = &[
    0x85, 0xff, 0x75, 0x08, 0x83, 0xee, 0x05, 0x75, 0x03, 0x89, 0xf0, 0xc3, 0x31, 0xc0, 0xc3,
];

/// The same, but the function returns 1: the subtraction is only its flags.
const SECOND_TEST_ONLY_COMPARES: &[u8] = &[
    0x85, 0xff, 0x75, 0x0b, 0x83, 0xee, 0x05, 0x75, 0x06, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0x31,
    0xc0, 0xc3,
];

#[test]
fn a_second_test_joins_the_chain_only_if_it_computes_nothing_the_function_keeps() {
    // r2ssa says both blocks owe nothing but their branch and what they carry; only the text
    // knows whether the subtraction is a statement of its own, which no `&&` may drop.
    let kept = c_of(SECOND_TEST_KEEPS_ITS_VALUE);
    assert_eq!(tests_of(&kept).len(), 2, "{kept}");
    assert!(!kept.contains(" && "), "{kept}");
    assert!(kept.contains("arg1 - (uint32_t)5U"), "{kept}");
    let flags = c_of(SECOND_TEST_ONLY_COMPARES);
    assert_eq!(tests_of(&flags).len(), 1, "{flags}");
    assert!(flags.contains(" && "), "{flags}");
}

/// `xor eax, eax; jmp test; body: inc eax; test: cmp eax, edi; jl body; ret`
const COUNT_UP: &[u8] = &[
    0x31, 0xc0, 0xeb, 0x02, 0xff, 0xc0, 0x39, 0xf8, 0x7c, 0xfa, 0xc3,
];

#[test]
fn a_loop_that_tests_before_its_body_is_a_while() {
    let c = c_of(COUNT_UP);
    assert_eq!(c.matches("while (").count(), 1, "{c}");
    assert!(!c.contains("for (; ; )") && !c.contains("break"), "{c}");
    // The test is the machine's: stay while the counter is below the bound.
    let test = c
        .lines()
        .find(|line| line.contains("while ("))
        .expect("a loop");
    assert!(test.contains('<'), "{c}");
}

/// `xor eax, eax; test: cmp eax, edi; jge done; inc eax; jmp test; done: ret`: the header leaves the
/// loop when its jump is taken.
const COUNT_UNTIL: &[u8] = &[
    0x31, 0xc0, 0x39, 0xf8, 0x7d, 0x04, 0xff, 0xc0, 0xeb, 0xf8, 0xc3,
];

#[test]
fn a_loop_that_leaves_when_its_jump_is_taken_stays_on_the_opposite_test() {
    let c = c_of(COUNT_UNTIL);
    let test = c
        .lines()
        .find(|line| line.contains("while ("))
        .unwrap_or_else(|| panic!("a while: {c}"));
    // `jge done` leaves once i >= arg0, so the loop stays while arg0 > i, and the text says that.
    assert!(
        test.contains("arg0 > ") && !test.contains(">=") && !test.contains('!'),
        "{c}"
    );
    assert!(!c.contains("for (; ; )") && !c.contains("break"), "{c}");
}

/// `test edi, edi; je skip; xor eax, eax; body: inc eax; cmp eax, edi; jne body; ret; skip: xor eax, eax; ret`
const COUNT_TO: &[u8] = &[
    0x85, 0xff, 0x74, 0x09, 0x31, 0xc0, 0xff, 0xc0, 0x39, 0xf8, 0x75, 0xfa, 0xc3, 0x31, 0xc0, 0xc3,
];

#[test]
fn a_loop_that_tests_after_its_body_is_a_do_while_with_its_merge_copies_before_the_test() {
    let c = c_of(COUNT_TO);
    assert_eq!(c.matches("do {").count(), 1, "{c}");
    assert!(!c.contains("for (; ; )") && !c.contains("break"), "{c}");
    // The copy that carries the counter round the loop is written before the test reads the next value.
    let lines: Vec<&str> = c.lines().map(str::trim).collect();
    let end = lines
        .iter()
        .position(|line| line.starts_with("} while ("))
        .expect("a do-while");
    assert!(
        lines[end - 1].contains(" = ") && !lines[end - 1].contains("if"),
        "{c}"
    );
}

/// `test edi, edi; je skip; xor eax, eax; body: mov edx, eax; inc eax; cmp eax, edi; jne body; mov eax, edx;
/// ret; skip: xor eax, eax; ret`: the code after the loop wants the counter as the last iteration began it.
const LAST_BEGUN: &[u8] = &[
    0x85, 0xff, 0x74, 0x0d, 0x31, 0xc0, 0x89, 0xc2, 0xff, 0xc0, 0x39, 0xf8, 0x75, 0xf8, 0x89, 0xd0,
    0xc3, 0x31, 0xc0, 0xc3,
];

#[test]
fn what_the_code_after_a_loop_reads_is_not_what_the_hoisted_copy_writes() {
    // The result is the counter as the last iteration began it, which the text keeps in a variable
    // of its own, so the copy of the next value may still be written before the test.
    let c = c_of(LAST_BEGUN);
    let lines: Vec<&str> = c.lines().map(str::trim).collect();
    let end = lines
        .iter()
        .position(|line| line.starts_with("} while ("))
        .expect("a do-while");
    let copied = lines[end - 1].split(" = ").next().expect("a copy");
    let returned = lines
        .iter()
        .find(|line| line.starts_with("return (uint32_t)"))
        .expect("a return of the loop's value");
    assert!(!returned.contains(copied), "{c}");
}

/// `top: movzx edx, byte [rdi]; add rdi, 1; test dl, dl; je done; cmp dl, 0x3a; jne top; done: lea rax,
/// [rdi - 1]; ret`: the second test goes back to the first, so the chain's exits are `done` and its own head.
const SCAN_TO_SEPARATOR: &[u8] = &[
    0x0f, 0xb6, 0x17, 0x48, 0x83, 0xc7, 0x01, 0x84, 0xd2, 0x74, 0x05, 0x80, 0xfa, 0x3a, 0x75, 0xf0,
    0x48, 0x8d, 0x47, 0xff, 0xc3,
];

#[test]
fn a_chain_whose_exit_is_a_continue_to_its_own_head_is_one_test() {
    // Stop at a zero byte or a colon: the chain `c == 0 || c == 58` leaves, and its other exit is the
    // head itself, so the loop is a `do-while` on `c != 0 && c != 58` with nothing left to `break`.
    let c = c_of(SCAN_TO_SEPARATOR);
    let test = c
        .lines()
        .find(|line| line.contains("} while ("))
        .unwrap_or_else(|| panic!("a do-while: {c}"));
    assert!(
        test.contains(" && ") && test.contains("!= (uint8_t)0U"),
        "{c}"
    );
    assert!(!c.contains("for (; ; )") && !c.contains("break"), "{c}");
    assert_eq!(tests_of(&c).len(), 0, "{c}");
}

/// `xor eax, eax; top: movzx r8d, byte [rdi + rax]; mov [rdx], r8b; lea ecx, [rax + 1]; cmp eax, esi;
/// mov eax, ecx; jne top; xor eax, eax; ret`: the test compares the index the iteration began with.
const TEST_READS_THE_COPY_TARGET: &[u8] = &[
    0x31, 0xc0, 0x44, 0x0f, 0xb6, 0x04, 0x07, 0x44, 0x88, 0x02, 0x48, 0x8d, 0x48, 0x01, 0x39, 0xf0,
    0x40, 0x89, 0xc8, 0x75, 0xed, 0x31, 0xc0, 0xc3,
];

#[test]
fn a_copy_stays_on_its_arm_when_the_test_reads_the_variable_it_writes() {
    // Written before the test, `i = i + 1` would make `i != n` compare the next index, not this one.
    let c = c_of(TEST_READS_THE_COPY_TARGET);
    assert!(c.contains("for (; ; )") && !c.contains("do {"), "{c}");
    assert!(c.contains("!= (uint32_t)arg1"), "{c}");
}

/// A loop with two ways out before its latch (`je early` twice) to a tail of five stores that reads the index,
/// and a latch `lea ecx, [rax + 1]; mov eax, ecx; cmp eax, esi; jne top`.
const TAIL_READS_THE_COPY_TARGET: &[u8] = &[
    0x31, 0xc0, 0x44, 0x0f, 0xb6, 0x04, 0x07, 0x41, 0x80, 0xf8, 0x2c, 0x74, 0x0a, 0x45, 0x84, 0xc0,
    0x74, 0x1f, 0x44, 0x88, 0x02, 0xeb, 0x09, 0x45, 0x84, 0xc0, 0x74, 0x15, 0x44, 0x88, 0x42, 0x01,
    0x48, 0x8d, 0x48, 0x01, 0x40, 0x89, 0xc8, 0x39, 0xf0, 0x75, 0xd7, 0xb8, 0xff, 0xff, 0xff, 0xff,
    0xc3, 0x88, 0x42, 0x02, 0x88, 0x42, 0x03, 0x88, 0x42, 0x04, 0x88, 0x42, 0x05, 0x88, 0x42, 0x06,
    0xc3,
];

#[test]
fn a_copy_stays_on_its_arm_when_code_after_the_loop_reads_what_it_writes() {
    // The tail after the loop reads `i`, and nothing here says which of the loop's exits reaches it,
    // so the copy is written only where the loop goes on (ADR §5).
    let c = c_of(TAIL_READS_THE_COPY_TARGET);
    assert!(c.contains("for (; ; )") && !c.contains("do {"), "{c}");
    let tail = c
        .split("L2: ;")
        .nth(1)
        .unwrap_or_else(|| panic!("a tail: {c}"));
    assert!(tail.contains("rax_2"), "{c}");
}

/// `push rbx; xor ebx, ebx; top: call 0x2000; inc ebx; test eax, eax; jne top; mov eax, ebx; pop rbx; ret`:
/// the test reads a call's result, which nothing proves.
const TEST_READS_AN_UNPROVEN_CALL: &[u8] = &[
    0x53, 0x31, 0xdb, 0xe8, 0xf8, 0x0f, 0x00, 0x00, 0xff, 0xc3, 0x85, 0xc0, 0x75, 0xf5, 0x40, 0x89,
    0xd8, 0x5b, 0xc3,
];

#[test]
fn a_copy_stays_on_its_arm_when_the_test_is_not_a_proven_read() {
    // The copy is not moved across a test that traps where its cell is unproven (ADR §5).
    let c = c_of(TEST_READS_AN_UNPROVEN_CALL);
    assert!(c.contains("for (; ; )") && !c.contains("do {"), "{c}");
    assert!(c.contains("r2sleigh_residual_u64"), "{c}");
}

/// `top: movzx edx, byte [rdi]; test dl, dl; je done; cmp dl, 0x3a; jne top; done: xor eax, eax; ret`: nothing
/// is copied on the way round, so the chain is spelled on the side the loop leaves by.
const SPIN_UNTIL_SEPARATOR: &[u8] = &[
    0x0f, 0xb6, 0x17, 0x84, 0xd2, 0x74, 0x05, 0x80, 0xfa, 0x3a, 0x75, 0xf4, 0x31, 0xc0, 0xc3,
];

#[test]
fn a_loop_that_leaves_on_a_chain_stays_on_both_tests_negated() {
    // It leaves when `c == 0 || c == 58`, so it stays when `c != 0 && c != 58`: the connective swaps with the tests.
    let c = c_of(SPIN_UNTIL_SEPARATOR);
    let test = c
        .lines()
        .find(|line| line.contains("} while ("))
        .unwrap_or_else(|| panic!("a do-while: {c}"));
    assert_eq!(test.matches(" && ").count(), 1, "{c}");
    assert!(
        !test.contains(" || ") && test.matches("!= (uint8_t)").count() == 2,
        "{c}"
    );
}

/// The four write orders a placement can be asked for: the natural one and the three mutants (ROADMAP D58).
const ORDERS: [WriteOrder; 4] = [
    WriteOrder::Natural,
    WriteOrder::KeepExits,
    WriteOrder::ExitsReversed,
    WriteOrder::MergesReversed,
];

/// What no block write order may change: the ledger's columns, the never-assigned names and the set of
/// statements apart from control and site numbers (a set: a tail is written once per jump to it).
#[derive(Debug, PartialEq, Eq)]
struct Verdicts {
    ledger: String,
    never_assigned: String,
    statements: BTreeSet<String>,
}

fn verdicts_of(c: &str) -> Verdicts {
    let proof = c
        .lines()
        .find(|line| line.contains("r2dec proof:"))
        .unwrap_or_else(|| panic!("a proof line: {c}"));
    let between = |from: &str, to: char| {
        proof
            .split_once(from)
            .map(|(_, rest)| rest.split(to).next().unwrap_or_default().to_owned())
            .unwrap_or_default()
    };
    let site = regex_free_site_numbers;
    Verdicts {
        ledger: between("source obligations:", ';'),
        never_assigned: between("never assigned, read as residuals (", ')'),
        statements: c
            .lines()
            .map(str::trim)
            .filter(|line| line.ends_with(';') && !line.starts_with("goto "))
            .filter(|line| !matches!(*line, "break;" | "continue;") && !line.ends_with(": ;"))
            .map(site)
            .collect(),
    }
}

/// `line` with each residual site's number replaced by `N`: sites are numbered in text order.
fn regex_free_site_numbers(line: &str) -> String {
    let mut out = String::new();
    let mut rest = line;
    while let Some(at) = rest.find("r2sleigh_residual_") {
        let (head, tail) = rest.split_at(at);
        out.push_str(head);
        let open = tail.find('(').map_or(tail.len(), |open| open + 1);
        out.push_str(&tail[..open]);
        let digits = tail[open..]
            .chars()
            .take_while(char::is_ascii_digit)
            .count();
        out.push('N');
        rest = &tail[open + digits..];
    }
    out.push_str(rest);
    out
}

/// A rendering of `code` with blocks written in `order`; each is a fresh program, so no memo is shared.
fn c_under(order: WriteOrder, code: &'static [u8]) -> String {
    with_write_order(order, || c_of(code))
}

/// The lines that name the variable `name` other than as the target of an assignment to it.
fn reads_of<'c>(c: &'c str, name: &str) -> Vec<&'c str> {
    c.lines()
        .map(str::trim)
        .filter(|line| line.contains(name) && !line.starts_with(&format!("{name} = ")))
        .filter(|line| !line.ends_with(&format!(" {name};")))
        .collect()
}

/// `sub rsp, 0x18; lea rax, [rsp + 8]; loop: cmp byte [rdi], 0; je out; cmp sil, [rdi]; je found;
/// add rax, 1; add rdi, 1; jmp loop; out: add rsp, 0x18; ret; found: add rax, 5; add rsp, 0x18; ret`
const FRAME_ADDRESS_LOOP: &[u8] = &[
    0x48, 0x83, 0xec, 0x18, 0x48, 0x8d, 0x44, 0x24, 0x08, 0x80, 0x3f, 0x00, 0x74, 0x0f, 0x40, 0x3a,
    0x37, 0x74, 0x0f, 0x48, 0x83, 0xc0, 0x01, 0x48, 0x83, 0xc7, 0x01, 0xeb, 0xec, 0x48, 0x83, 0xc4,
    0x18, 0xc3, 0x48, 0x83, 0xc0, 0x05, 0x48, 0x83, 0xc4, 0x18, 0xc3,
];

/// The same, with `test rdx, rdx; je found2` before the loop: a second way to the exit that adds 5,
/// which makes that exit a merge written after the loop whichever order the exits are written in.
const FRAME_ADDRESS_LOOP_TWO_WAYS: &[u8] = &[
    0x48, 0x83, 0xec, 0x18, 0x48, 0x8d, 0x44, 0x24, 0x08, 0x48, 0x85, 0xd2, 0x74, 0x19, 0x80, 0x3f,
    0x00, 0x74, 0x0f, 0x40, 0x3a, 0x37, 0x74, 0x0f, 0x48, 0x83, 0xc0, 0x01, 0x48, 0x83, 0xc7, 0x01,
    0xeb, 0xec, 0x48, 0x83, 0xc4, 0x18, 0xc3, 0x48, 0x83, 0xc0, 0x05, 0x48, 0x83, 0xc4, 0x18, 0xc3,
];

#[test]
fn a_merge_whose_entry_copy_is_a_gap_reads_as_a_residual_under_every_write_order() {
    // The loop's merge enters with a frame address (a gap); its only other copy is the latch's.
    let mut texts = BTreeSet::new();
    for code in [FRAME_ADDRESS_LOOP, FRAME_ADDRESS_LOOP_TWO_WAYS] {
        let natural = c_under(WriteOrder::Natural, code);
        assert!(natural.contains("ValuesNotRendered"), "{natural}");
        let verdicts = verdicts_of(&natural);
        for order in ORDERS {
            let c = c_under(order, code);
            assert_eq!(verdicts_of(&c), verdicts, "{order:?}\n{c}");
            texts.insert(c);
        }
        // The loop's merge has no value on its way in, so no write order reads it as a variable.
        assert!(verdicts.never_assigned.contains("RAX_2"), "{natural}");
        for order in ORDERS {
            let c = c_under(order, code);
            let reads = reads_of(&c, "rax_2");
            assert!(
                reads
                    .iter()
                    .all(|line| line.contains("r2sleigh_residual_u64(")),
                "{order:?}: {reads:?}\n{c}"
            );
        }
    }
    // The orders do move the text (the knob is live), or equal verdicts would prove nothing.
    assert!(
        texts.len() > 2,
        "the orders wrote {} distinct texts",
        texts.len()
    );
}

/// `sub rsp, 0x18; test rdi, rdi; je other; lea rax, [rsp + 8]; jmp join; other: mov rax, rsi;
/// join: add rsp, 0x18; ret`: one way into the join carries a frame address, which is a gap.
const ONE_GAPPED_COPY: &[u8] = &[
    0x48, 0x83, 0xec, 0x18, 0x48, 0x85, 0xff, 0x74, 0x07, 0x48, 0x8d, 0x44, 0x24, 0x08, 0xeb, 0x03,
    0x48, 0x89, 0xf0, 0x48, 0x83, 0xc4, 0x18, 0xc3,
];

#[test]
fn a_merge_with_one_gapped_forward_copy_reads_as_a_residual() {
    // A gap traps where it stands, but the certificate lets control go on past it, so the value the
    // merge holds on the other way in is no proof that a read of it is defined.
    for order in ORDERS {
        let c = c_under(order, ONE_GAPPED_COPY);
        assert!(c.contains("ValuesNotRendered"), "{order:?}\n{c}");
        assert!(
            verdicts_of(&c).never_assigned.contains("RAX_3"),
            "{order:?}\n{c}"
        );
        let reads = reads_of(&c, "rax_3");
        assert!(
            reads
                .iter()
                .all(|line| line.contains("r2sleigh_residual_u64(")),
            "{order:?}: {reads:?}\n{c}"
        );
    }
}

/// `test rdi, rdi; je other; mov rax, rsi; jmp join; other: mov rax, rdx; join: ret`
const BOTH_COPIES_RENDER: &[u8] = &[
    0x48, 0x85, 0xff, 0x74, 0x05, 0x48, 0x89, 0xf0, 0xeb, 0x03, 0x48, 0x89, 0xd0, 0xc3, 0x90, 0x90,
];

#[test]
fn a_merge_whose_forward_copies_all_render_reads_as_a_variable_in_every_order() {
    let natural = verdicts_of(&c_under(WriteOrder::Natural, BOTH_COPIES_RENDER));
    assert_eq!(natural.never_assigned, "");
    for order in ORDERS {
        let c = c_under(order, BOTH_COPIES_RENDER);
        assert_eq!(verdicts_of(&c), natural, "{order:?}\n{c}");
        assert!(!c.contains("r2sleigh_residual_"), "{order:?}\n{c}");
        assert!(c.contains("return (uint64_t)rax_3;"), "{order:?}\n{c}");
    }
}

/// `xor eax, eax; test edi, edi; je y; x: add eax, 1; cmp eax, esi; jl y; ret; y: add eax, 2; cmp eax, edx;
/// jl x; ret`: two ways into the cycle x, y, so neither dominates the other and one edge of it is late.
const IRREDUCIBLE: &[u8] = &[
    0x31, 0xc0, 0x85, 0xff, 0x74, 0x08, 0x83, 0xc0, 0x01, 0x39, 0xf0, 0x7c, 0x01, 0xc3, 0x83, 0xc0,
    0x02, 0x39, 0xd0, 0x7c, 0xf1, 0xc3,
];

#[test]
fn a_merge_entered_late_by_an_irreducible_edge_reads_as_a_variable_when_every_copy_renders() {
    // The edge that closes the cycle is spelled after the reads of the merge it enters, and renders its
    // copy, so those reads are defined; no write order and no spelling order changes that.
    let natural = c_under(WriteOrder::Natural, IRREDUCIBLE);
    assert!(!natural.contains("r2sleigh_residual_"), "{natural}");
    for order in ORDERS {
        let c = c_under(order, IRREDUCIBLE);
        assert_eq!(verdicts_of(&c), verdicts_of(&natural), "{order:?}\n{c}");
        assert!(!c.contains("r2sleigh_residual_"), "{order:?}\n{c}");
    }
}

/// `sub rsp, 0x18; xor eax, eax; test edi, edi; je y; x: lea rax, [rsp + 8]; test esi, esi; jne y; add rsp,
/// 0x18; ret; y: add eax, 1; test edx, edx; jne x; add rsp, 0x18; ret`: the late edge carries a frame address.
const IRREDUCIBLE_GAPPED: &[u8] = &[
    0x48, 0x83, 0xec, 0x18, 0x31, 0xc0, 0x85, 0xff, 0x74, 0x0e, 0x48, 0x8d, 0x44, 0x24, 0x08, 0x85,
    0xf6, 0x75, 0x05, 0x48, 0x83, 0xc4, 0x18, 0xc3, 0x83, 0xc0, 0x01, 0x85, 0xd2, 0x75, 0xeb, 0x48,
    0x83, 0xc4, 0x18, 0xc3,
];

#[test]
fn a_merge_entered_late_by_a_gapped_copy_reads_as_a_residual_whatever_was_promised_before() {
    // The reads of the merge are spelled before the late edge, as variables on its promise; the edge
    // gaps, so the function is spelled again with that merge owed one more.
    let natural = verdicts_of(&c_under(WriteOrder::Natural, IRREDUCIBLE_GAPPED));
    let carried = natural.never_assigned.to_lowercase();
    assert!(!carried.is_empty() && !carried.contains(','), "{natural:?}");
    for order in ORDERS {
        let c = c_under(order, IRREDUCIBLE_GAPPED);
        assert_eq!(verdicts_of(&c), natural, "{order:?}\n{c}");
        assert!(c.contains("ValuesNotRendered"), "{order:?}\n{c}");
        let reads = reads_of(&c, &carried);
        assert!(
            reads
                .iter()
                .all(|line| line.contains("r2sleigh_residual_u64(")),
            "{order:?}: {reads:?}\n{c}"
        );
    }
}

/// The bytes of `body` at `BASE`, then `atan2f`'s linkage stub (`jmp qword [rip + 2]`) and its slot at `STUB`.
const fn with_the_atan2f_stub(body: &[u8]) -> [u8; 0xa0] {
    let mut bytes = [0xcc; 0xa0];
    let mut at = 0;
    while at < body.len() {
        bytes[at] = body[at];
        at += 1;
    }
    let stub = [0xff, 0x25, 0x02, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut at = 0;
    while at < stub.len() {
        bytes[0x90 + at] = stub[at];
        at += 1;
    }
    bytes
}

/// `lane_nondom9`: `xmm1` merges two loads; one arm of `ucomiss xmm4, xmm2` calls `atan2f(xmm4, xmm1)`, the
/// other reads its low lane (`comiss xmm1, xmm2`). The listing is in the D68 section of the ADR.
static LANE_READ_BESIDE_THE_CALL: [u8; 0xa0] = with_the_atan2f_stub(&[
    0x48, 0x83, 0xec, 0x08, 0xf3, 0x0f, 0x10, 0x62, 0x10, 0xf3, 0x0f, 0x10, 0x52, 0x14, 0x48, 0x85,
    0xff, 0x74, 0x06, 0xf3, 0x0f, 0x10, 0x0e, 0xeb, 0x05, 0xf3, 0x0f, 0x10, 0x4e, 0x04, 0x0f, 0x2e,
    0xe2, 0x76, 0x0a, 0x0f, 0x2f, 0xca, 0x76, 0x12, 0x48, 0x83, 0xc4, 0x08, 0xc3, 0x0f, 0x28, 0xc4,
    0xe8, 0x5b, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x08, 0xc3, 0x48, 0x83, 0xc4, 0x08, 0xc3,
]);

/// The same with the branch the other way: `ja call`, so the call is on the taken edge.
static LANE_READ_BESIDE_THE_TAKEN_CALL: [u8; 0xa0] = with_the_atan2f_stub(&[
    0x48, 0x83, 0xec, 0x08, 0xf3, 0x0f, 0x10, 0x62, 0x10, 0xf3, 0x0f, 0x10, 0x52, 0x14, 0x48, 0x85,
    0xff, 0x74, 0x06, 0xf3, 0x0f, 0x10, 0x0e, 0xeb, 0x05, 0xf3, 0x0f, 0x10, 0x4e, 0x04, 0x0f, 0x2e,
    0xe2, 0x77, 0x0a, 0x0f, 0x2f, 0xca, 0x76, 0x12, 0x48, 0x83, 0xc4, 0x08, 0xc3, 0x0f, 0x28, 0xc4,
    0xe8, 0x5b, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x08, 0xc3, 0x48, 0x83, 0xc4, 0x08, 0xc3,
]);

/// The same as the first with the call on the fall-through edge and the lane read on the taken one.
static LANE_READ_BESIDE_THE_FALLTHROUGH_CALL: [u8; 0xa0] = with_the_atan2f_stub(&[
    0x48, 0x83, 0xec, 0x08, 0xf3, 0x0f, 0x10, 0x62, 0x10, 0xf3, 0x0f, 0x10, 0x52, 0x14, 0x48, 0x85,
    0xff, 0x74, 0x06, 0xf3, 0x0f, 0x10, 0x0e, 0xeb, 0x05, 0xf3, 0x0f, 0x10, 0x4e, 0x04, 0x0f, 0x2e,
    0xe2, 0x76, 0x0d, 0x0f, 0x28, 0xc4, 0xe8, 0x65, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x08, 0xc3,
    0x0f, 0x2f, 0xca, 0x76, 0x05, 0x48, 0x83, 0xc4, 0x08, 0xc3, 0x48, 0x83, 0xc4, 0x08, 0xc3,
]);

/// `c`, rendered from `code` with blocks written in `order`, the program importing `atan2f` at its stub.
fn atan2f_caller_under(order: WriteOrder, code: &'static [u8]) -> String {
    with_write_order(order, || {
        let literal = Literal::of_code(code, &[("f", BASE, 0x3f)])
            .importing("atan2f")
            .running_on(common::GLIBC);
        OpenProgram::of(literal)
            .rendered(BASE)
            .expect("it renders")
            .response
            .output
            .into_text()
    })
}

/// The identifier `text` starts with.
fn identifier(text: &str) -> String {
    text.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// The locals a rendering declares: the lines of its preamble that are `type name;`.
fn locals_of(c: &str) -> BTreeSet<String> {
    c.lines()
        .map(str::trim)
        .take_while(|line| !line.starts_with("/*"))
        .filter_map(|line| line.strip_suffix(';'))
        .filter(|line| !line.contains(['(', '=']))
        .map(|line| {
            line.rsplit([' ', '*'])
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

/// The locals read in `args`, the text after a call's opening parenthesis, that `assigned` lacks.
fn unassigned_in(
    args: &str,
    locals: &BTreeSet<String>,
    assigned: &BTreeSet<String>,
) -> Vec<String> {
    let mut unassigned = Vec::new();
    let mut rest = args;
    while !rest.is_empty() {
        let name = identifier(rest);
        let skip = name.len().max(1).min(rest.len());
        if locals.contains(&name) && !assigned.contains(&name) {
            unassigned.push(name);
        }
        rest = &rest[skip..];
    }
    unassigned
}

/// What a path to a statement has assigned, or `None` where it returned: a path meet keeps what both assign.
type Assigned = Option<BTreeSet<String>>;

fn meet(a: Assigned, b: Assigned) -> Assigned {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.intersection(&b).cloned().collect()),
        (a, None) => a,
        (None, b) => b,
    }
}

/// An `if` being read: what was assigned before it, and at the end of its then arm once that is read.
enum Frame {
    Block,
    If {
        before: Assigned,
        then_end: Option<Assigned>,
    },
}

/// The locals the first call to `callee` reads that some path to it leaves unassigned, over structured C:
/// `if`/`else`, bare blocks, `return` and assignments (a `goto` or a label is not read, and fails the test).
fn unassigned_at_call(c: &str, callee: &str) -> Vec<String> {
    let locals = locals_of(c);
    let call = format!("{callee}(");
    let mut assigned = Some(BTreeSet::<String>::new());
    let mut frames = Vec::<Frame>::new();
    let body = c
        .lines()
        .skip_while(|line| !line.contains("/* r2dec proof"));
    for line in body.map(str::trim) {
        assert!(
            !line.starts_with("goto ") && !line.ends_with(": ;"),
            "structured C only: {c}"
        );
        if line == "{" {
            frames.push(Frame::Block);
        } else if line.starts_with("if (") && line.ends_with('{') {
            let before = assigned.clone();
            frames.push(Frame::If {
                before,
                then_end: None,
            });
        } else if line == "} else {" {
            let Some(Frame::If { before, then_end }) = frames.last_mut() else {
                panic!("an else without an if: {c}");
            };
            *then_end = Some(assigned.take());
            assigned.clone_from(before);
        } else if line == "}" {
            assigned = match frames.pop() {
                Some(Frame::If {
                    then_end: Some(then_end),
                    ..
                }) => meet(then_end, assigned.take()),
                Some(Frame::If { before, .. }) => meet(assigned.take(), before),
                _ => assigned.take(),
            };
        } else if line.starts_with("return") {
            assigned = None;
        } else if let Some(at) = line.find(&call) {
            let Some(assigned) = &assigned else { continue };
            return unassigned_in(&line[at + call.len()..], &locals, assigned);
        } else if let Some((target, _)) = line.split_once(" = ")
            && let Some(set) = &mut assigned
        {
            set.insert(identifier(target));
        }
    }
    panic!("no call to {callee}: {c}")
}

#[test]
fn a_call_argument_is_never_a_lane_that_only_the_other_arm_assigns_under_every_write_order() {
    // The lane is read where the call is not dominated by it: the argument is the carrier, or a
    // residual, never the lane (ROADMAP D68).
    for (layout, code) in [
        ("lane_nondom9", &LANE_READ_BESIDE_THE_CALL),
        ("lane_nondom7", &LANE_READ_BESIDE_THE_TAKEN_CALL),
        ("lane_nondom8", &LANE_READ_BESIDE_THE_FALLTHROUGH_CALL),
    ] {
        for order in ORDERS {
            let c = atan2f_caller_under(order, code);
            let arguments = common::call_arguments(&c, "atan2f")
                .unwrap_or_else(|| panic!("{layout} {order:?}: no call\n{c}"));
            assert_eq!(arguments.len(), 2, "{layout} {order:?}\n{c}");
            assert_eq!(
                unassigned_at_call(&c, "atan2f"),
                Vec::<String>::new(),
                "{layout} {order:?}\n{c}"
            );
            assert!(
                arguments[1].contains("r2sleigh_residual_") || arguments[1].contains("xmm1_"),
                "{layout} {order:?}: {arguments:?}\n{c}"
            );
        }
    }
}

#[test]
fn a_lane_the_facts_name_on_the_other_arm_is_read_as_a_residual_not_as_a_variable() {
    // The knob states the lane as r2ssa did before D68; the renderer's own rule still makes the read a
    // residual, which the proof line names (ROADMAP D68).
    for (layout, code, named) in [
        ("lane_nondom9", &LANE_READ_BESIDE_THE_CALL, true),
        ("lane_nondom7", &LANE_READ_BESIDE_THE_TAKEN_CALL, true),
        // Here the lane's block is spelled after the call's, so the write is not yet spelled.
        (
            "lane_nondom8",
            &LANE_READ_BESIDE_THE_FALLTHROUGH_CALL,
            false,
        ),
    ] {
        for order in ORDERS {
            let facts = r2ssa::fact_mutants::Facts::UnsoundLanesUnchecked;
            let c = r2ssa::fact_mutants::with_facts(facts, || atan2f_caller_under(order, code));
            let arguments = common::call_arguments(&c, "atan2f")
                .unwrap_or_else(|| panic!("{layout} {order:?}: no call\n{c}"));
            assert!(
                arguments[1].contains("r2sleigh_residual_"),
                "{layout} {order:?}: {arguments:?}\n{c}"
            );
            assert_eq!(
                unassigned_at_call(&c, "atan2f"),
                Vec::<String>::new(),
                "{c}"
            );
            assert_eq!(
                c.contains("assigned on only some paths to its read"),
                named,
                "{layout} {order:?}\n{c}"
            );
        }
    }
}

#[test]
fn a_lane_the_facts_name_on_the_other_arm_refuses_the_function_while_r2ssa_checks_its_facts() {
    // With only the pick unsound, r2ssa refuses what it states itself (ROADMAP D68): no C is written.
    let facts = r2ssa::fact_mutants::Facts::UnsoundLanes;
    for code in [
        &LANE_READ_BESIDE_THE_CALL,
        &LANE_READ_BESIDE_THE_TAKEN_CALL,
        &LANE_READ_BESIDE_THE_FALLTHROUGH_CALL,
    ] {
        let c = r2ssa::fact_mutants::with_facts(facts, || {
            atan2f_caller_under(WriteOrder::Natural, code)
        });
        assert!(
            c.contains("refused f: SSA integrity: a boundary fact names a value"),
            "{c}"
        );
        assert!(!c.contains("atan2f("), "{c}");
    }
}

/// `code` written at `TWO` over a program importing `import`, with the rel32 of each `call` in `calls`
/// (offsets into `code`, the opcode byte) pointed at the import's stub.
fn c_calling(import: &str, code: &[u8], calls: &[usize]) -> String {
    let mut code = code.to_vec();
    for &at in calls {
        assert_eq!(code[at], 0xe8, "a call at {at:#x}");
        let rel = i32::try_from(common::STUB as i64 - (common::TWO + at as u64 + 5) as i64)
            .expect("near");
        code[at + 1..at + 5].copy_from_slice(&rel.to_le_bytes());
    }
    let mut program = OpenProgram::of(Literal::new().importing(import).running_on(common::GLIBC));
    program.source_mut().write(common::TWO, &code);
    (program.rendered(common::TWO))
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// `test edi, edi; jne cold; mov eax, 7; ret; cold: mov edi, 1; call <import>`: the arm taken calls out.
const COLD_CALL: &[u8] = &[
    0x85, 0xff, 0x75, 0x06, 0xb8, 0x07, 0, 0, 0, 0xc3, 0xbf, 1, 0, 0, 0, 0xe8, 0, 0, 0, 0,
];

/// `test edi, edi; je rest; mov edi, 1; call <import>; rest: mov eax, 7; ret`: the arm not taken calls out.
const FALLING_CALL: &[u8] = &[
    0x85, 0xff, 0x74, 0x0a, 0xbf, 1, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0xb8, 0x07, 0, 0, 0, 0xc3,
];

/// `test edi, edi; jne cold; mov dword [rsi], 7; jmp join; cold: mov edi, 1; call <import>; join: xor eax, eax; ret`
const JOINED_CALL: &[u8] = &[
    0x85, 0xff, 0x75, 0x08, 0xc7, 0x06, 0x07, 0, 0, 0, 0xeb, 0x0a, 0xbf, 1, 0, 0, 0, 0xe8, 0, 0, 0,
    0, 0x31, 0xc0, 0xc3,
];

/// The same with `call rax` for the call: nothing states that it does not return.
const JOINED_INDIRECT: &[u8] = &[
    0x85, 0xff, 0x75, 0x08, 0xc7, 0x06, 0x07, 0, 0, 0, 0xeb, 0x02, 0xff, 0xd0, 0x31, 0xc0, 0xc3,
];

/// `test edi, edi; jne a; mov [rdx], 5; test esi, esi; jne b; mov eax, 7; ret; a: mov edi, 1; call exit;
/// b: mov edi, 2; call exit`
const TWO_GUARDS: &[u8] = &[
    0x85, 0xff, 0x75, 0x10, 0xc7, 0x02, 0x05, 0, 0, 0, 0x85, 0xf6, 0x75, 0x10, 0xb8, 0x07, 0, 0, 0,
    0xc3, 0xbf, 1, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0xbf, 2, 0, 0, 0, 0xe8, 0, 0, 0, 0,
];

/// The indent of the first line holding `needle`, and its position among the lines.
fn line_of(c: &str, needle: &str) -> (usize, usize) {
    let (at, line) = (c.lines().enumerate())
        .find(|(_, line)| line.contains(needle))
        .unwrap_or_else(|| panic!("a line with {needle}: {c}"));
    (at, line.len() - line.trim_start().len())
}

#[test]
fn an_arm_that_ends_in_a_call_declared_never_to_return_is_a_guard_and_the_rest_follows_it() {
    // `if (c) exit(1); else return 7;` is `if (c) exit(1); return 7;`: the call does not come back.
    let c = c_calling("exit", COLD_CALL, &[0x0f]);
    assert!(!c.contains("r2sleigh refused"), "{c}");
    assert_eq!(tests_of(&c).len(), 1, "{c}");
    assert!(!c.contains("else"), "{c}");
    let (test, exit, rest) = (
        line_of(&c, "if ("),
        line_of(&c, "exit(1)"),
        line_of(&c, "return 7"),
    );
    // The call is in the `if`, and the return is after it, on the `if`'s own level.
    assert!(test.0 < exit.0 && exit.0 < rest.0, "{c}");
    assert_eq!((exit.1 > test.1, rest.1), (true, test.1), "{c}");
}

#[test]
fn what_the_machine_runs_after_the_test_is_written_after_the_guard_in_the_machine_s_order() {
    // The guard takes the else arm's statements out of the else, never past one another: the store
    // stays between the two tests, and neither test moves before it.
    let c = c_calling("exit", TWO_GUARDS, &[0x19, 0x23]);
    assert!(!c.contains("r2sleigh refused"), "{c}");
    assert_eq!(tests_of(&c).len(), 2, "{c}");
    assert!(!c.contains("else"), "{c}");
    let at = |needle: &str| line_of(&c, needle).0;
    let order = [at("exit(1)"), at("5U)"), at("exit(2)"), at("return 7")];
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]), "{c}");
    let tests: Vec<_> = c
        .lines()
        .enumerate()
        .filter(|(_, line)| line.trim_start().starts_with("if "))
        .collect();
    assert!(
        tests[0].0 < order[0] && order[1] < tests[1].0 && tests[1].0 < order[2],
        "{c}"
    );
}

#[test]
fn a_guard_keeps_the_statements_of_the_arm_it_frees() {
    // The store is on the arm that does not exit, and it runs before the return after the join.
    let c = c_calling("exit", JOINED_CALL, &[0x11]);
    assert!(!c.contains("r2sleigh refused"), "{c}");
    assert!(!c.contains("else"), "{c}");
    let (test, exit, store, ret) = (
        line_of(&c, "if ("),
        line_of(&c, "exit(1)"),
        line_of(&c, "7U)"),
        line_of(&c, "return 0"),
    );
    assert!(
        test.0 < exit.0 && exit.0 < store.0 && store.0 < ret.0,
        "{c}"
    );
    // The merge after the join is a block of its own, one level in.
    assert_eq!((store.1, ret.1 > test.1), (test.1, true), "{c}");
}

#[test]
fn an_import_the_container_does_not_declare_never_to_return_keeps_its_else() {
    // The arm ends in `puts`, which comes back and runs `return 0` as the other arm does.
    let c = c_calling("puts", JOINED_CALL, &[0x11]);
    assert!(c.contains("puts("), "{c}");
    assert!(c.contains("else"), "{c}");
    assert!(!c.contains("noreturn"), "{c}");
}

#[test]
fn a_call_through_a_register_keeps_its_else() {
    let c = c_calling("exit", JOINED_INDIRECT, &[]);
    assert!(c.contains("else"), "{c}");
}

#[test]
fn an_else_arm_that_never_returns_is_a_guard_on_the_opposite_test() {
    // `if (c == 0) return 7; else exit(1);` is `if (c != 0) exit(1); return 7;`: the call is the guard's
    // body, so the test is the machine's other edge, written once over the test's own atom.
    let c = c_calling("exit", FALLING_CALL, &[0x09]);
    assert!(!c.contains("r2sleigh refused"), "{c}");
    assert!(!c.contains("else") && !c.contains("(!"), "{c}");
    let test = tests_of(&c);
    assert_eq!(test.len(), 1, "{c}");
    assert!(test[0].contains("!= (uint32_t)0U"), "{c}");
    let (guard, exit, rest) = (
        line_of(&c, "if ("),
        line_of(&c, "exit(1)"),
        line_of(&c, "return 7"),
    );
    assert!(
        guard.0 < exit.0 && exit.0 < rest.0 && rest.1 == guard.1,
        "{c}"
    );
}
