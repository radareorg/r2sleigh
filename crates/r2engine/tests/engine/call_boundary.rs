//! One `CallBoundary` per callee and world decides its result (doc/adr-call-boundary.md, D166).

use crate::common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;

/// `f`: `mov eax, 7; ret`; `caller`: `call f; mov [rsi], eax; ret`, which reads EAX as left.
const READ: &[u8] = &[
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1000 mov eax, 7
    0xc3, // 1005 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1006 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x89, 0x06, // 1015 mov [rsi], eax
    0xc3, // 1017 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1018 padding
];

/// A closed-world read makes a written result a value at `Solved`, and the premise is stated on the
/// proof line and in the response, apart from "no call reads"; a cold `pdd` keeps it unproven.
#[test]
fn a_closed_world_read_states_its_premise_and_a_cold_render_stays_unproven() {
    let program = || Literal::of_code(READ, &[("f", BASE, 0x06), ("caller", BASE + 0x10, 0x08)]);
    let cold = OpenProgram::of(program())
        .rendered(BASE)
        .expect("it renders");
    let text = cold.response.output.into_text();
    assert!(text.starts_with("r2sleigh_result_u64 f("), "{text}");
    assert!(
        !cold
            .response
            .premises
            .contains(&r2source::Premise::ClosedWorld)
    );
    let mut open = OpenProgram::of(program());
    open.analyse_program().expect("it surveys");
    let analysed = open.rendered(BASE).expect("it renders");
    assert!(
        analysed
            .response
            .premises
            .contains(&r2source::Premise::ClosedWorld),
        "{:?}",
        analysed.response.premises
    );
    let text = analysed.response.output.into_text();
    assert!(text.starts_with("uint64_t f("), "{text}");
    assert!(
        text.contains("a call reads the result (assuming closed-world)"),
        "{text}"
    );
    assert!(!text.contains("no call reads the result"), "{text}");
}

/// AArch64 `keep`: `mov x2, #0x2000; str x1, [x2]; ret`, which hands back x0 as it arrived, and
/// `caller`: `bl keep; str x0, [x3]; ret`. `long keep(long x, long y){sink=y; return x;}` and
/// `void f(long x, long y){sink=y;}` are these bytes, so `keep` is never `void` (D208).
const KEEP: &[u8] = &[
    0x02, 0x00, 0x84, 0xd2, // 1000 mov x2, #0x2000
    0x41, 0x00, 0x00, 0xf9, // 1004 str x1, [x2]
    0xc0, 0x03, 0x5f, 0xd6, // 1008 ret
    0x1f, 0x20, 0x03, 0xd5, // 100c nop
    0xfc, 0xff, 0xff, 0x97, // 1010 bl 0x1000
    0x60, 0x00, 0x00, 0xf9, // 1014 str x0, [x3]
    0xc0, 0x03, 0x5f, 0xd6, // 1018 ret
    0x1f, 0x20, 0x03, 0xd5, // 101c nop
];

#[test]
fn an_aarch64_keep_is_never_void() {
    let program = || {
        Literal::of_code(KEEP, &[("keep", BASE, 0x0c), ("caller", BASE + 0x10, 0x0c)]).in_aarch64()
    };
    let cold = OpenProgram::of(program())
        .rendered(BASE)
        .expect("it renders");
    let text = cold.response.output.into_text();
    assert!(!text.starts_with("void keep("), "{text}");
    assert!(text.contains("EntryInput"), "{text}");
    let mut open = OpenProgram::of(program());
    open.analyse_program().expect("it surveys");
    let text = open
        .rendered(BASE)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(!text.starts_with("void keep("), "{text}");
}

/// `f`: `mov eax, 7; ret`; `caller`: `call f; xor eax, eax; xor edx, edx; xorps xmm0, xmm0;
/// xorps xmm1, xmm1; ret`, which writes every lane `f` may hold before reading any.
const UNREAD: &[u8] = &[
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1000 mov eax, 7
    0xc3, // 1005 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1006 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x31, 0xc0, // 1015 xor eax, eax
    0x31, 0xd2, // 1017 xor edx, edx
    0x0f, 0x57, 0xc0, // 1019 xorps xmm0, xmm0
    0x0f, 0x57, 0xc9, // 101c xorps xmm1, xmm1
    0xc3, // 101f ret
];

/// Every call leaves every lane `f` may hold dead: the written result is unread, never void (D202).
#[test]
fn a_written_result_no_call_reads_is_unread_never_void() {
    let program = Literal::of_code(UNREAD, &[("f", BASE, 0x06), ("caller", BASE + 0x10, 0x10)]);
    let mut open = OpenProgram::of(program);
    open.analyse_program().expect("it surveys");
    let text = open
        .rendered(BASE)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(text.starts_with("r2sleigh_result_u64 f("), "{text}");
    assert!(text.contains("unproven (Unread)"), "{text}");
    assert!(
        text.contains("no call reads the result (assuming closed-world)"),
        "{text}"
    );
}
