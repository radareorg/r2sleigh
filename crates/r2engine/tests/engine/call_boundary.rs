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

/// AArch64 `keep` (`mov x2, #0x2000; str x1, [x2]; ret`) hands back x0; `caller` is `bl keep;
/// str x0, [x3]; ret`. `void f(long x, long y){sink=y;}` has `keep`'s bytes: never `void` (D208).
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

/// `f`: `mov eax, 7; ret`; `g`: `call f; mov al, 0; ret`; `caller`: `call g; mov [rsi], al; ret`.
const LOW_BYTE_OVERWRITTEN: &[u8] = &[
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1000 mov eax, 7
    0xc3, // 1005 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1006 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0xb0, 0x00, // 1015 mov al, 0
    0xc3, // 1017 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1018 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1020 call 0x1010
    0x88, 0x06, // 1025 mov [rsi], al
    0xc3, // 1027 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1028 padding
];

/// `g` returns `f`'s bytes 1 to 7 and its own AL, the one byte `caller` reads: no byte of `f`'s
/// reaches a read, so forwarding proves no read of `f`'s result.
#[test]
fn a_forwarded_read_of_bytes_the_forwarder_wrote_is_no_read_of_the_callee() {
    let functions = [
        ("f", BASE, 0x06),
        ("g", BASE + 0x10, 0x08),
        ("caller", BASE + 0x20, 0x08),
    ];
    let mut open = OpenProgram::of(Literal::of_code(LOW_BYTE_OVERWRITTEN, &functions));
    open.analyse_program().expect("it surveys");
    let text = (open.rendered(BASE).expect("it renders").response.output).into_text();
    assert!(text.starts_with("r2sleigh_result_u64 f("), "{text}");
    assert!(!text.contains("a call reads the result"), "{text}");
}

/// `a`: `test edi, edi; je 1f; call b; ret; 1: mov eax, 1; ret`; `b` the same over `esi`, calling
/// `a`; `c`: `call b; ret`; `d`: `call c; mov [rsi], eax; ret`. `a` and `b` forward into each other.
const FORWARDING_CYCLE: &[u8] = &[
    0x85, 0xff, // 1000 test edi, edi
    0x74, 0x06, // 1002 je 0x100a
    0xe8, 0x07, 0x00, 0x00, 0x00, // 1004 call 0x1010
    0xc3, // 1009 ret
    0xb8, 0x01, 0x00, 0x00, 0x00, // 100a mov eax, 1
    0xc3, // 100f ret
    0x85, 0xf6, // 1010 test esi, esi
    0x74, 0x06, // 1012 je 0x101a
    0xe8, 0xe7, 0xff, 0xff, 0xff, // 1014 call 0x1000
    0xc3, // 1019 ret
    0xb8, 0x01, 0x00, 0x00, 0x00, // 101a mov eax, 1
    0xc3, // 101f ret
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1020 call 0x1010
    0xc3, // 1025 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1026 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1030 call 0x1020
    0x89, 0x06, // 1035 mov [rsi], eax
    0xc3, // 1037 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1038 padding
];

/// What the closed world decides of `a`'s and `b`'s results once `order` is prepared after `aa`.
fn closed_after(order: &[u64]) -> Vec<Option<r2source::SourceClosedResult>> {
    let functions = [
        ("a", BASE, 0x10),
        ("b", BASE + 0x10, 0x10),
        ("c", BASE + 0x20, 0x06),
        ("d", BASE + 0x30, 0x08),
    ];
    let mut open = OpenProgram::of(Literal::of_code(FORWARDING_CYCLE, &functions));
    open.analyse_program().expect("it surveys");
    for &entry in order {
        open.prepared(entry).expect("it prepares");
    }
    [BASE, BASE + 0x10]
        .iter()
        .map(|&entry| {
            let prepared = open.prepared(entry).expect("it prepares");
            let shared = prepared.artifact().shared_artifact();
            let interface = shared.machine_context().function_interface();
            interface.and_then(r2source::SourceFunctionInterface::closed_result)
        })
        .collect()
}

/// A forwarding cycle's answer is the same whichever of its functions is asked first (AGENTS 7).
#[test]
fn a_forwarding_cycle_decides_the_same_whichever_function_is_asked_first() {
    let a_first = closed_after(&[BASE]);
    let b_first = closed_after(&[BASE + 0x10]);
    assert_eq!(a_first, b_first);
    assert!(
        a_first
            .iter()
            .all(|decided| matches!(decided, Some(r2source::SourceClosedResult::Read(_)))),
        "{a_first:?}"
    );
}

/// `UNREAD`, then `mov eax, 1; ret` at 0x1020, which no function holds.
const UNREAD_BESIDE_CODE: &[u8] = &[
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1000 mov eax, 7
    0xc3, // 1005 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1006 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x31, 0xc0, // 1015 xor eax, eax
    0x31, 0xd2, // 1017 xor edx, edx
    0x0f, 0x57, 0xc0, // 1019 xorps xmm0, xmm0
    0x0f, 0x57, 0xc9, // 101c xorps xmm1, xmm1
    0xc3, // 101f ret
    0xb8, 0x01, 0x00, 0x00, 0x00, // 1020 mov eax, 1
    0xc3, // 1025 ret
];

/// Code no body holds may call `f`, so the calls read are not every way in: the closed world refuses
/// before it builds the reference index, and the result stays unproven with no premise.
#[test]
fn code_no_body_holds_refuses_the_closed_world_before_the_reference_index() {
    let program = Literal::of_code(
        UNREAD_BESIDE_CODE,
        &[("f", BASE, 0x06), ("caller", BASE + 0x10, 0x10)],
    );
    let mut open = OpenProgram::of(program);
    open.analyse_program().expect("it surveys");
    let rendering = open.rendered(BASE).expect("it renders");
    let text = rendering.response.output.into_text();
    assert!(text.starts_with("r2sleigh_result_u64 f("), "{text}");
    assert!(!text.contains("no call reads the result"), "{text}");
    assert!(
        !rendering
            .response
            .premises
            .contains(&r2source::Premise::ClosedWorld)
    );
    assert_eq!(open.analysis_stats().references.computed, 0);
}
