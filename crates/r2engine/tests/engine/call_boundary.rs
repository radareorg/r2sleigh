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
    assert!(text.starts_with("r2sleigh_result_u32 f("), "{text}");
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
    assert!(text.starts_with("uint32_t f("), "{text}");
    // The premise is its own clause, never a column of the obligation list (D234).
    assert!(
        text.contains("; a call reads the result (assuming closed-world)"),
        "{text}"
    );
    assert!(!text.contains("refused, a call"), "{text}");
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
    // The return the text shows as a residual is counted, never "0 carried" alone (D233).
    assert!(text.contains("return r2sleigh_residual_u64(1);"), "{text}");
    assert!(
        text.contains("0 unproven-return carried, 1 unproven-return residual"),
        "{text}"
    );
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
    assert!(text.starts_with("r2sleigh_result_u32 f("), "{text}");
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
    assert!(text.starts_with("r2sleigh_result_u32 f("), "{text}");
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
    assert!(text.starts_with("r2sleigh_result_u32 f("), "{text}");
    assert!(!text.contains("no call reads the result"), "{text}");
    assert!(
        !rendering
            .response
            .premises
            .contains(&r2source::Premise::ClosedWorld)
    );
    assert_eq!(open.analysis_stats().references.computed, 0);
}

/// `f`: `pxor xmm0, xmm0; mov eax, 7; ret`; `g`: `call f; ret`; `caller_a`: `call g; movss [rsi],
/// xmm0; ret`; `caller_b`: `call g; movsd [rsi], xmm0; ret`.
const FORWARDED_AT_TWO_WIDTHS: &[u8] = &[
    0x66, 0x0f, 0xef, 0xc0, // 1000 pxor xmm0, xmm0
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1004 mov eax, 7
    0xc3, // 1009 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 100a padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0xc3, // 1015 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1016 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1020 call 0x1010
    0xf3, 0x0f, 0x11, 0x06, // 1025 movss [rsi], xmm0
    0xc3, // 1029 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 102a padding
    0xe8, 0xdb, 0xff, 0xff, 0xff, // 1030 call 0x1010
    0xf2, 0x0f, 0x11, 0x06, // 1035 movsd [rsi], xmm0
    0xc3, // 1039 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 103a padding
];

/// `g`'s callers read XMM0 as a `float` and as a `double`: forwarded through `g`, the reads still
/// disagree, so `f` proves no width, where their joined bytes would make it a `double`.
#[test]
fn forwarded_float_reads_at_two_widths_prove_no_result() {
    let functions = [
        ("f", BASE, 0x0a),
        ("g", BASE + 0x10, 0x06),
        ("caller_a", BASE + 0x20, 0x0a),
        ("caller_b", BASE + 0x30, 0x0a),
    ];
    let mut open = OpenProgram::of(Literal::of_code(FORWARDED_AT_TWO_WIDTHS, &functions));
    open.analyse_program().expect("it surveys");
    let text = (open.rendered(BASE).expect("it renders").response.output).into_text();
    assert!(!text.starts_with("double f("), "{text}");
    assert!(!text.starts_with("float f("), "{text}");
}

/// `k` functions in a ring, each `test edi, edi; je 1f; call next; ret; 1: mov eax, 1; ret`, then
/// `c`: `call f0; ret` and `d`: `call c; mov [rsi], eax; ret`.
fn forwarding_ring(k: u64) -> Literal {
    let mut code = Vec::new();
    for at in 0..k {
        let next = BASE + 0x10 * ((at + 1) % k);
        let rel = (next.wrapping_sub(BASE + 0x10 * at + 9) as u32).to_le_bytes();
        code.extend([0x85, 0xff, 0x74, 0x06, 0xe8]);
        code.extend(rel);
        code.extend([0xc3, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
    }
    let c = BASE + 0x10 * k;
    code.extend([0xe8]);
    code.extend((BASE.wrapping_sub(c + 5) as u32).to_le_bytes());
    code.extend([0xc3; 11]);
    code.extend([0xe8]);
    code.extend((c.wrapping_sub(c + 0x10 + 5) as u32).to_le_bytes());
    code.extend([0x89, 0x06, 0xc3]);
    code.extend([0xcc; 24]);
    let names = (0..k).map(|at| format!("f{at}")).collect::<Vec<_>>();
    let mut functions = (names.iter().enumerate())
        .map(|(at, name)| (name.as_str(), BASE + 0x10 * at as u64, 0x10))
        .collect::<Vec<_>>();
    functions.extend([("c", c, 6), ("d", c + 0x10, 8)]);
    Literal::of_code(Box::leak(code.into_boxed_slice()), &functions)
}

/// The forwarder-graph nodes and the boundaries one request computes over a forwarding ring of `k`.
fn ring_work(k: u64) -> (u64, u64) {
    let mut open = OpenProgram::of(forwarding_ring(k));
    open.analyse_program().expect("it surveys");
    let before = open.analysis_stats();
    open.prepared(BASE).expect("it prepares");
    let after = open.analysis_stats();
    (
        after.direct_sites.computed - before.direct_sites.computed,
        after.call_boundaries.computed - before.call_boundaries.computed,
    )
}

/// A forwarding ring is one component solved once: each function's calls are joined once, where
/// asking per lane computed 3,282 boundaries for a ring of 8.
#[test]
fn a_forwarding_ring_is_solved_once_per_caller() {
    for k in [2, 8] {
        let (nodes, boundaries) = ring_work(k);
        assert!(nodes <= k + 2, "ring {k}: {nodes} joins");
        assert!(
            boundaries <= 2 * (k + 2),
            "ring {k}: {boundaries} boundaries"
        );
    }
}

/// `h`: `mov eax, 7; ret`; `g`: `call h; ret`; `caller`: `call g; movsd [rsi], xmm0; ret`. No
/// body writes XMM0, so the read is the caller's own bytes.
const UNWRITTEN_FLOAT_READ: &[u8] = &[
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1000 mov eax, 7
    0xc3, // 1005 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1006 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0xc3, // 1015 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1016 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1020 call 0x1010
    0xf2, 0x0f, 0x11, 0x06, // 1025 movsd [rsi], xmm0
    0xc3, // 1029 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 102a padding
];

/// A read of a lane no body writes proves no result: neither `h` nor `g` is a `double` (default-deny).
#[test]
fn a_read_of_a_lane_no_body_writes_decides_no_result() {
    let functions = [
        ("h", BASE, 0x06),
        ("g", BASE + 0x10, 0x06),
        ("caller", BASE + 0x20, 0x0a),
    ];
    let mut open = OpenProgram::of(Literal::of_code(UNWRITTEN_FLOAT_READ, &functions));
    open.analyse_program().expect("it surveys");
    for at in [BASE, BASE + 0x10] {
        let text = (open.rendered(at).expect("it renders").response.output).into_text();
        assert!(!text.contains("double "), "{text}");
    }
}

/// `f`: `lea rax, [rdi + 1]; cvtsi2sd xmm0, rdi; ret`; `g`: `sub rsp, 0x28; call f; add rsp,
/// 0x28; ret`; `caller`: `call g; movsd [rsi], xmm0; ret`.
const FORWARDED_FLOAT: &[u8] = &[
    0x48, 0x8d, 0x47, 0x01, // 1000 lea rax, [rdi + 1]
    0xf2, 0x48, 0x0f, 0x2a, 0xc7, // 1004 cvtsi2sd xmm0, rdi
    0xc3, // 1009 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 100a padding
    0x48, 0x83, 0xec, 0x28, // 1010 sub rsp, 0x28
    0xe8, 0xe7, 0xff, 0xff, 0xff, // 1014 call 0x1000
    0x48, 0x83, 0xc4, 0x28, // 1019 add rsp, 0x28
    0xc3, // 101d ret
    0x90, 0x90, // 101e padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1020 call 0x1010
    0xf2, 0x0f, 0x11, 0x06, // 1025 movsd [rsi], xmm0
    0xc3, // 1029 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 102a padding
];

/// `g` hands back the `double` `f` states in XMM0, which `caller` reads: never `void`, though the
/// call leaves RAX outside `f`'s result (the f3 struct forwarders, gcc -O1).
#[test]
fn a_forwarder_of_a_stated_float_result_its_caller_reads_is_never_void() {
    let functions = [
        ("f", BASE, 0x0a),
        ("g", BASE + 0x10, 0x0e),
        ("caller", BASE + 0x20, 0x0a),
    ];
    let mut open = OpenProgram::of(Literal::of_code(FORWARDED_FLOAT, &functions));
    open.analyse_program().expect("it surveys");
    let mut header = |at| (open.rendered(at).expect("it renders").response.output).into_text();
    let text = header(BASE);
    assert!(text.starts_with("double f("), "{text}");
    let text = header(BASE + 0x10);
    assert!(text.starts_with("double g("), "{text}");
}

/// `f` is `ret`: RAX defines nothing and XMM0 holds its entry byte; `hlt` and a multi-byte `nop` pad
/// it. `caller` is `call f; mov [rsi], eax; mov [rdi], rdx; xorps xmm0, xmm0; xorps xmm1, xmm1; ret`.
const HANDED_BACK: &[u8] = &[
    0xc3, // 1000 ret
    0xf4, // 1001 hlt
    0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, // 1002 nop word [rax + rax]
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1008 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x89, 0x06, // 1015 mov [rsi], eax
    0x48, 0x89, 0x17, // 1017 mov [rdi], rdx
    0x0f, 0x57, 0xc0, // 101a xorps xmm0, xmm0
    0x0f, 0x57, 0xc9, // 101d xorps xmm1, xmm1
    0xc3, // 1020 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1021 padding
];

/// `caller` reads XMM0 as `f` handed it back: `call f; movsd [rsi], xmm0; xorps xmm1, xmm1; ret`.
const FLOAT_READ: &[u8] = &[
    0xc3, // 1000 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xe8,
    0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0xf2, 0x0f, 0x11, 0x06, // 1015 movsd [rsi], xmm0
    0x0f, 0x57, 0xc9, // 1019 xorps xmm1, xmm1
    0xc3, // 101c ret
    0x90, 0x90, 0x90,
];

/// `f` is `ret` and nothing calls it: `caller` is `xor eax, eax; ret`.
const UNCALLED: &[u8] = &[
    0xc3, // 1000 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x31,
    0xc0, // 1010 xor eax, eax
    0xc3, // 1012 ret
    0x90,
];

fn analysed(program: Literal) -> String {
    let mut open = OpenProgram::of(program);
    open.analyse_program().expect("it surveys");
    let rendered = open.rendered(BASE).expect("it renders");
    rendered.response.output.into_text()
}

/// D213: an entry-input lane every call leaves dead is void under `aa`, with the premise; a read of
/// RAX or RDX, which the body defines nothing in, reads the caller's own bytes. Cold, EntryInput.
#[test]
fn an_entry_input_lane_every_call_leaves_dead_is_void_under_the_closed_world() {
    let program = || {
        Literal::of_code(
            HANDED_BACK,
            &[("f", BASE, 0x01), ("caller", BASE + 0x10, 0x11)],
        )
    };
    let cold = OpenProgram::of(program())
        .rendered(BASE)
        .expect("it renders");
    let text = cold.response.output.into_text();
    assert!(text.contains("EntryInput"), "{text}");
    let text = analysed(program());
    assert!(text.starts_with("void f("), "{text}");
    assert!(text.contains("(assuming closed-world)"), "{text}");
}

/// A call that reads the XMM0 bytes `f` hands back keeps the result unproven.
#[test]
fn an_entry_input_lane_a_call_reads_is_never_void() {
    let program = Literal::of_code(
        FLOAT_READ,
        &[("f", BASE, 0x01), ("caller", BASE + 0x10, 0x0d)],
    );
    let text = analysed(program);
    assert!(!text.starts_with("void f("), "{text}");
}

/// `caller` stores ST0 after `call f`: the x87 stack is empty on entry (SysV 3.2.1), so `f` holds no
/// result there and the read is no evidence: `f` is void under `aa`.
const X87_READ: &[u8] = &[
    0xc3, // 1000 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xe8,
    0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0xdd, 0x1e, // 1015 fstp qword [rsi]
    0x0f, 0x57, 0xc0, // 1017 xorps xmm0, xmm0
    0x0f, 0x57, 0xc9, // 101a xorps xmm1, xmm1
    0xc3, // 101d ret
    0x90, 0x90,
];

/// `mid` is `call f; ret`, handing back what `f` left; `top` is `call mid; xorps xmm0, xmm0; xorps
/// xmm1, xmm1; ret`. The lanes `f` hands back die in `top`'s call: void, through `mid`.
const FORWARDED: &[u8] = &[
    0xc3, // 1000 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xe8,
    0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0xc3, // 1015 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1016 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1020 call 0x1010
    0x0f, 0x57, 0xc0, // 1025 xorps xmm0, xmm0
    0x0f, 0x57, 0xc9, // 1028 xorps xmm1, xmm1
    0xc3, // 102b ret
    0x90, 0x90, 0x90, 0x90,
];

/// `f` is `pxor xmm0, xmm0; ret`: a written float lane, which every call leaves dead.
const WRITTEN_FLOAT: &[u8] = &[
    0x66, 0x0f, 0xef, 0xc0, // 1000 pxor xmm0, xmm0
    0xc3, // 1004 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xe8, 0xeb, 0xff, 0xff,
    0xff, // 1010 call 0x1000
    0x0f, 0x57, 0xc0, // 1015 xorps xmm0, xmm0
    0x0f, 0x57, 0xc9, // 1018 xorps xmm1, xmm1
    0xc3, // 101b ret
    0x90, 0x90, 0x90, 0x90,
];

#[test]
fn an_x87_read_after_the_call_is_no_evidence_against_void() {
    let program = Literal::of_code(
        X87_READ,
        &[("f", BASE, 0x01), ("caller", BASE + 0x10, 0x0e)],
    );
    let text = analysed(program);
    assert!(text.starts_with("void f("), "{text}");
}

#[test]
fn an_entry_input_lane_a_caller_returns_into_a_dead_call_is_void() {
    let functions = [
        ("f", BASE, 0x01),
        ("mid", BASE + 0x10, 0x06),
        ("top", BASE + 0x20, 0x0c),
    ];
    let text = analysed(Literal::of_code(FORWARDED, &functions));
    assert!(text.starts_with("void f("), "{text}");
}

/// A written lane no call reads is unread, never void (D202), where the integer register holds nothing.
#[test]
fn a_written_float_no_call_reads_is_unread_never_void() {
    let program = Literal::of_code(
        WRITTEN_FLOAT,
        &[("f", BASE, 0x05), ("caller", BASE + 0x10, 0x0c)],
    );
    let text = analysed(program);
    assert!(!text.starts_with("void f("), "{text}");
    assert!(text.contains("unproven (Unread)"), "{text}");
}

/// A stored pointer to `f` is a way in no call shows: never void.
#[test]
fn an_entry_input_lane_a_pointer_enters_is_never_void() {
    let mut program = Literal::of_code(
        UNCALLED,
        &[("f", BASE, 0x01), ("caller", BASE + 0x10, 0x03)],
    );
    program.write(BASE + 0x08, &0x1000u64.to_le_bytes());
    let text = analysed(program);
    assert!(!text.starts_with("void f("), "{text}");
}

/// A function nothing calls keeps its open result: no call executes it, so no fact decides it
/// (doc/adr-result-side.md, section 3, the one-call minimum).
#[test]
fn an_entry_input_lane_nothing_calls_keeps_its_open_result() {
    let program = Literal::of_code(
        UNCALLED,
        &[("f", BASE, 0x01), ("caller", BASE + 0x10, 0x03)],
    );
    let text = analysed(program);
    assert!(!text.starts_with("void f("), "{text}");
    assert!(text.contains("EntryInput"), "{text}");
    assert!(!text.contains("closed-world"), "{text}");
}

/// `HANDED_BACK`'s `f` and `caller`, then `other` at 0x1028 (`ret`, room for an 8-byte instruction),
/// and 16 bytes at 0x1030 the tests map as data for a stored word.
const WAYS_IN: &[u8] = &[
    0xc3, // 1000 ret
    0xf4, // 1001 hlt
    0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, // 1002 nop word [rax + rax]
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1008 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x89, 0x06, // 1015 mov [rsi], eax
    0x48, 0x89, 0x17, // 1017 mov [rdi], rdx
    0x0f, 0x57, 0xc0, // 101a xorps xmm0, xmm0
    0x0f, 0x57, 0xc9, // 101d xorps xmm1, xmm1
    0xc3, // 1020 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1021 padding
    0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1028 other: ret
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1030 data
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1038 data
];

/// `WAYS_IN` with its code ending at 0x1030 and the data after it.
fn ways_in() -> Literal {
    let functions = [
        ("f", BASE, 0x08),
        ("caller", BASE + 0x10, 0x11),
        ("other", BASE + 0x28, 0x08),
    ];
    Literal::of_code(WAYS_IN, &functions).with_data_after(BASE + 0x30)
}

/// A word the loader writes at 0x1030.
fn loader_word(kind: r2engine::program::WriteKind) -> r2engine::program::LoaderWrite {
    r2engine::program::LoaderWrite {
        place: BASE + 0x30,
        width: 8,
        kind,
        encoding: r2abi::statement::Encoding::Word,
    }
}

/// Every way into `f` the closed world reads (doc/adr-result-side.md, "The closed world"), each alone.
fn each_way_in() -> Vec<(&'static str, Literal)> {
    use r2engine::program::WriteKind;
    let exported = ways_in().declaring(r2abi::statement::Symbol {
        name: "f".into(),
        vaddr: BASE,
        size: 0x08,
        kind: r2abi::statement::SymbolKind::Function,
        defined: true,
        origin: r2abi::statement::SymbolOrigin {
            table: None,
            dynamic: Some(1),
            directory: None,
        },
        ..r2abi::statement::Symbol::default()
    });
    let entered = ways_in().entering(BASE, r2abi::statement::EntryKind::Init);
    let mut named = ways_in();
    // 1028 lea rdi, [rip - 0x2f] (0x1000); 102f ret
    named.write(
        BASE + 0x28,
        &[0x48, 0x8d, 0x3d, 0xd1, 0xff, 0xff, 0xff, 0xc3],
    );
    let mut word = ways_in();
    word.write(BASE + 0x30, &0x1000u64.to_le_bytes());
    let mut half = ways_in();
    // Four bytes name `f`; no eight-byte window holds it.
    half.write(
        BASE + 0x30,
        &[0x00, 0x10, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
    );
    let mut thumb = ways_in();
    thumb.write(BASE + 0x30, &0x1001u64.to_le_bytes());
    let relative = ways_in().loader_written(loader_word(WriteKind::Relative(BASE)));
    let resolver = ways_in().loader_written(loader_word(WriteKind::Resolver(BASE)));
    let unknown = ways_in().loader_written(loader_word(WriteKind::Unknown));
    let mut unaccounted = ways_in();
    // 1021 mov eax, 1; 1026 ret: code in no function, which may call or name anything.
    unaccounted.write(BASE + 0x21, &[0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]);
    let foreign = ways_in().in_language(r2engine::program::SourceLanguage::ObjectiveC);
    // 1012 lost, inside `caller`'s call: `ff ff` decodes to nothing, so no walk reads its body.
    let unwalked = ways_in().stating("lost", BASE + 0x12);
    vec![
        ("exported", exported),
        ("an entry no symbol states", entered),
        ("named by an instruction", named),
        ("an 8-byte stored word", word),
        ("a 4-byte stored word", half),
        ("a stored word with the Thumb bit", thumb),
        ("a relative loader write", relative),
        ("a resolver loader write", resolver),
        ("an unknown loader write", unknown),
        ("code no body holds", unaccounted),
        ("a language whose tables hold offsets", foreign),
        ("a body no walk reads", unwalked),
    ]
}

/// The program `each_way_in` varies: `f`'s lanes die at its one call, so it is void under `aa`.
#[test]
fn every_way_in_is_read_before_a_closed_world_void() {
    let text = analysed(ways_in());
    assert!(text.starts_with("void f("), "{text}");
    for (way, program) in each_way_in() {
        let text = analysed(program);
        assert!(!text.starts_with("void f("), "{way}: {text}");
        assert!(!text.contains("closed-world"), "{way}: {text}");
    }
}

/// `WAYS_IN`'s `f` and `caller`; `stop` at 0x1028 never returns, `g` at 0x1030 calls it, and the 11
/// bytes at 0x1035 are `g`'s code laid out as if the call came back (bzip2 `BZ2_bz__AssertH__fail`).
const AFTER_AN_EXIT: &[u8] = &[
    0xc3, // 1000 ret
    0xf4, // 1001 hlt
    0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, // 1002 nop word [rax + rax]
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1008 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x89, 0x06, // 1015 mov [rsi], eax
    0x48, 0x89, 0x17, // 1017 mov [rdi], rdx
    0x0f, 0x57, 0xc0, // 101a xorps xmm0, xmm0
    0x0f, 0x57, 0xc9, // 101d xorps xmm1, xmm1
    0xc3, // 1020 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1021 padding
    0xeb, 0xfe, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1028 stop: jmp 0x1028
    0xe8, 0xf3, 0xff, 0xff, 0xff, // 1030 g: call 0x1028
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1035 after the call
];

/// `AFTER_AN_EXIT` with `code` at 0x1035.
fn after_an_exit(code: &[u8]) -> Literal {
    let functions = [
        ("f", BASE, 0x08),
        ("caller", BASE + 0x10, 0x11),
        ("stop", BASE + 0x28, 0x02),
        ("g", BASE + 0x30, 0x05),
    ];
    let mut program = Literal::of_code(AFTER_AN_EXIT, &functions);
    program.write(BASE + 0x35, code);
    program
}

/// D244: code after a call that never returns is in no body. It is held where each instruction
/// decodes, transfers only to known code and names no function; what it names is a way in.
#[test]
fn code_after_an_exit_is_held_where_everything_it_names_escapes() {
    // 1035 mov edx, eax; 1037 test edx, edx; 1039 jg 0x1030; 103b jmp 0x1030
    let quiet = [0x89, 0xc2, 0x85, 0xd2, 0x7f, 0xf5, 0xeb, 0xf3];
    let text = analysed(after_an_exit(&quiet));
    assert!(text.starts_with("void f("), "{text}");
    assert!(text.contains("closed-world"), "{text}");
    // 1035 call 0x1000; 103a jmp 0x1030
    let calls = [0xe8, 0xc6, 0xff, 0xff, 0xff, 0xeb, 0xf4];
    // 1035 lea rax, [rip - 0x3c] (0x1000); 103c jmp 0x1030
    let names = [0x48, 0x8d, 0x05, 0xc4, 0xff, 0xff, 0xff, 0xeb, 0xf2];
    // 1035 mov edx, eax; 1037 jmp rax
    let indirect = [0x89, 0xc2, 0xff, 0xe0];
    // 1035 mov edx, eax; 1037 syscall; 1039 jmp 0x1030
    let supervisor = [0x89, 0xc2, 0x0f, 0x05, 0xeb, 0xf5];
    // 1035 mov eax, 0x1002; 103a sub eax, 2; 103d jmp 0x1030: `f`'s address, in no operand.
    let computed = [0xb8, 0x02, 0x10, 0x00, 0x00, 0x83, 0xe8, 0x02, 0xeb, 0xf1];
    let refused = [
        ("a computed address", &computed[..]),
        ("a call to f", &calls[..]),
        ("f's address", &names[..]),
        ("an indirect jump", &indirect[..]),
        ("a supervisor call", &supervisor[..]),
    ];
    for (what, code) in refused {
        let text = analysed(after_an_exit(code));
        assert!(!text.starts_with("void f("), "{what}: {text}");
    }
    // The quiet code after `caller`'s `ret` follows no exit: 1021 mov edx, eax; 1023 jmp 0x1010.
    let mut after_a_return = ways_in();
    after_a_return.write(BASE + 0x21, &[0x89, 0xc2, 0xeb, 0xeb]);
    let text = analysed(after_a_return);
    assert!(!text.starts_with("void f("), "{text}");
}

/// A `CallBoundary` decides from the open read and its forwarder component alone: no decision reaches
/// a function sealed in the closed world, nor another decision (doc/adr-result-side.md, section 5).
#[test]
fn a_call_boundary_reaches_no_closed_seal() {
    let programs = [
        Literal::of_code(
            HANDED_BACK,
            &[("f", BASE, 0x01), ("caller", BASE + 0x10, 0x11)],
        ),
        Literal::of_code(
            FORWARDED,
            &[
                ("f", BASE, 0x01),
                ("mid", BASE + 0x10, 0x06),
                ("top", BASE + 0x20, 0x0c),
            ],
        ),
        Literal::of_code(
            FORWARDER_CYCLE,
            &[
                ("f", BASE, 0x01),
                ("a", BASE + 0x10, 0x18),
                ("b", BASE + 0x30, 0x13),
            ],
        ),
        forwarding_ring(4),
        ways_in(),
    ];
    for program in programs {
        let mut open = OpenProgram::of(program);
        open.analyse_program().expect("it surveys");
        for entry in [BASE, BASE + 0x10, BASE + 0x20, BASE + 0x30] {
            let _ = open.rendered(entry);
        }
        assert_eq!(open.analysis_stats().defects, 0);
    }
}

/// `f` is `ret`. `a` and `b` each return early on a zero argument, else call the other and return
/// what it left; `a` calls `f` first and kills XMM0 after, `b` kills XMM1: the question ends.
const FORWARDER_CYCLE: &[u8] = &[
    0xc3, // 1000 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x85,
    0xff, // 1010 test edi, edi
    0x74, 0x0e, // 1012 jz 0x1022
    0xe8, 0xe7, 0xff, 0xff, 0xff, // 1014 call 0x1000
    0xe8, 0x12, 0x00, 0x00, 0x00, // 1019 call 0x1030
    0x0f, 0x57, 0xc0, // 101e xorps xmm0, xmm0
    0xc3, // 1021 ret
    0xb8, 0x01, 0x00, 0x00, 0x00, // 1022 mov eax, 1
    0xc3, // 1027 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1028 padding
    0x85, 0xff, // 1030 test edi, edi
    0x74, 0x09, // 1032 jz 0x103d
    0xe8, 0xd7, 0xff, 0xff, 0xff, // 1034 call 0x1010
    0x0f, 0x57, 0xc9, // 1039 xorps xmm1, xmm1
    0xc3, // 103c ret
    0xb8, 0x01, 0x00, 0x00, 0x00, // 103d mov eax, 1
    0xc3, // 1042 ret
    0x90, 0x90, 0x90, 0x90, 0x90,
];

#[test]
fn forwarders_that_forward_to_each_other_end() {
    let functions = [
        ("f", BASE, 0x01),
        ("a", BASE + 0x10, 0x18),
        ("b", BASE + 0x30, 0x13),
    ];
    let text = analysed(Literal::of_code(FORWARDER_CYCLE, &functions));
    assert!(!text.starts_with("void f("), "{text}");
    assert!(!text.contains("closed-world"), "{text}");
}

/// `store_through` writes 9 through its seventh argument; `caller` passes `&local` there, on the
/// stack at `[rsp]`, from `r11`, which no convention passes, and reads `local` back.
const SEVENTH: &[u8] = &[
    0x48, 0x8b, 0x44, 0x24, 0x08, // 1000 mov rax, [rsp + 0x8]: the seventh argument
    0xc7, 0x00, 0x09, 0x00, 0x00, 0x00, // 1005 mov dword [rax], 9
    0xc3, // 100b ret
    0xcc, 0xcc, 0xcc, 0xcc, // 100c padding
    0x48, 0x83, 0xec, 0x18, // 1010 sub rsp, 0x18
    0xc7, 0x44, 0x24, 0x10, 0x05, 0x00, 0x00, 0x00, // 1014 mov dword [rsp + 0x10], 5
    0x4c, 0x8d, 0x5c, 0x24, 0x10, // 101c lea r11, [rsp + 0x10]
    0x4c, 0x89, 0x1c, 0x24, // 1021 mov [rsp], r11
    0x31, 0xff, // 1025 xor edi, edi
    0x31, 0xf6, // 1027 xor esi, esi
    0x31, 0xd2, // 1029 xor edx, edx
    0x31, 0xc9, // 102b xor ecx, ecx
    0x45, 0x31, 0xc0, // 102d xor r8d, r8d
    0x45, 0x31, 0xc9, // 1030 xor r9d, r9d
    0xe8, 0xc8, 0xff, 0xff, 0xff, // 1033 call 0x1000
    0x8b, 0x44, 0x24, 0x10, // 1038 mov eax, [rsp + 0x10]
    0x48, 0x83, 0xc4, 0x18, // 103c add rsp, 0x18
    0xc3, // 1040 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

/// A local whose address is the seventh SysV argument stays in memory: the callee reads the
/// outgoing slot that holds it, so its store stands before the call and its read after (D217).
#[test]
fn a_local_passed_as_the_seventh_argument_stays_in_memory() {
    let functions = [("store_through", BASE, 0xc), ("caller", BASE + 0x10, 0x31)];
    let mut open = OpenProgram::of(Literal::of_code(SEVENTH, &functions));
    let caller = open
        .rendered(BASE + 0x10)
        .expect("it renders")
        .response
        .output
        .into_text();
    common::assert_local_stays_in_memory(&caller);
}

/// `f` of the AArch64 programs below: off the page `adrp` builds, which would read as its address.
const F: u64 = BASE + 0x08;

/// AArch64 words at `BASE`, `printf`'s stub at `STUB` (`ldr x16, [slot]; br x16`) and its slot.
fn aarch64_with_printf(words: &[(u64, u32)]) -> &'static [u8] {
    let mut code = vec![0u8; 0xb0];
    for (at, word) in words {
        let at = (*at - BASE) as usize;
        code[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    code[0x90..0x94].copy_from_slice(&0x5800_0050u32.to_le_bytes());
    code[0x94..0x98].copy_from_slice(&0xd61f_0200u32.to_le_bytes());
    Box::leak(code.into_boxed_slice())
}

/// `f` is `ret`: it hands back x0 and q0 to q3 as its caller left them. `caller` builds the format
/// address in `held`, calls `f`, then `printf(format, 7)` with the format moved from `held`.
fn printing(held: u32, format: &[u8]) -> String {
    printing_from(held, format, false)
}

/// [`printing`], the format's bytes mapped writable where `writable`.
fn printing_from(held: u32, format: &[u8], writable: bool) -> String {
    let code = aarch64_with_printf(&[
        (F, 0xd65f_03c0),                              // ret
        (BASE + 0x10, 0xa9bf_7bfd),                    // stp x29, x30, [sp, #-16]!
        (BASE + 0x14, 0x9000_0000 | held),             // adrp xN, 0x1000
        (BASE + 0x18, 0x9102_8000 | held << 5 | held), // add xN, xN, #0xa0
        (BASE + 0x1c, 0x97ff_fffb),                    // bl f
        (BASE + 0x20, 0xaa00_03e0 | held << 16),       // mov x0, xN
        (BASE + 0x24, 0x5280_00e1),                    // mov w1, #7
        (BASE + 0x28, 0x9400_001a),                    // bl printf
        (BASE + 0x2c, 0xa8c1_7bfd),                    // ldp x29, x30, [sp], #16
        (BASE + 0x30, 0xd65f_03c0),                    // ret
    ]);
    let program = Literal::of_code(code, &[("f", F, 0x04), ("caller", BASE + 0x10, 0x24)])
        .in_aarch64()
        .with_data()
        .importing("printf");
    let program = match writable {
        true => program.writable_data_after(common::TEXT),
        false => program,
    };
    let mut open = OpenProgram::of(program);
    open.source_mut().write(common::TEXT, format);
    open.analyse_program().expect("it surveys");
    let rendered = open.rendered(F).expect("it renders");
    rendered.response.output.into_text()
}

/// D218: a format with no floating conversion reads no vector register, so `f`'s q0 to q3 die at
/// `printf`: void under `aa`, the format held in x19, which the call to `f` preserves.
#[test]
fn an_aarch64_printf_whose_format_has_no_float_reads_no_vector_register() {
    let text = printing(19, b"%d\n\0");
    assert!(text.starts_with("void f("), "{text}");
    assert!(text.contains("(assuming closed-world)"), "{text}");
}

/// `%f` reads q0: `f`'s q0 reaches the call, so `f` is never void.
#[test]
fn an_aarch64_printf_whose_format_has_a_float_keeps_q0_read() {
    let text = printing(19, b"%f\n\0");
    assert!(!text.starts_with("void f("), "{text}");
}

/// x9 is caller-saved: the call to `f` may change it, so the format at `printf` is unknown and the
/// call may read every vector argument register.
#[test]
fn an_aarch64_printf_whose_format_a_call_may_change_reads_every_vector_register() {
    let text = printing(9, b"%d\n\0");
    assert!(!text.starts_with("void f("), "{text}");
}

/// A format in writable data may change before the call (Codex review of #363): the call may read
/// every vector argument register, so `f` is never void.
#[test]
fn an_aarch64_printf_whose_format_the_program_may_write_reads_every_vector_register() {
    let text = printing_from(19, b"%d\n\0", true);
    assert!(!text.starts_with("void f("), "{text}");
}

/// D219: `mid` (`bl f; mov x0, #5; ret`) hands back `f`'s q0 to q3; `top` reads `mid`'s x0, then
/// `printf("%d\n", x)` kills the rest. Decided per lane: `f` is void though `mid`'s result is read.
#[test]
fn a_lane_forwarded_through_a_caller_whose_result_is_read_is_decided_per_lane() {
    let code = aarch64_with_printf(&[
        (F, 0xd65f_03c0),           // f: ret
        (BASE + 0x10, 0xa9bf_7bfd), // mid: stp x29, x30, [sp, #-16]!
        (BASE + 0x14, 0x97ff_fffd), // bl f
        (BASE + 0x18, 0xd280_00a0), // mov x0, #5
        (BASE + 0x1c, 0xa8c1_7bfd), // ldp x29, x30, [sp], #16
        (BASE + 0x20, 0xd65f_03c0), // ret
        (BASE + 0x30, 0xa9bf_7bfd), // top: stp x29, x30, [sp, #-16]!
        (BASE + 0x34, 0x97ff_fff7), // bl mid
        (BASE + 0x38, 0xaa00_03e1), // mov x1, x0
        (BASE + 0x3c, 0x9000_0000), // adrp x0, 0x1000
        (BASE + 0x40, 0x9102_8000), // add x0, x0, #0xa0
        (BASE + 0x44, 0x9400_0013), // bl printf
        (BASE + 0x48, 0xa8c1_7bfd), // ldp x29, x30, [sp], #16
        (BASE + 0x4c, 0xd65f_03c0), // ret
    ]);
    let functions = [
        ("f", F, 0x04),
        ("mid", BASE + 0x10, 0x14),
        ("top", BASE + 0x30, 0x20),
    ];
    let program = Literal::of_code(code, &functions)
        .in_aarch64()
        .with_data()
        .importing("printf");
    let mut open = OpenProgram::of(program);
    open.source_mut().write(common::TEXT, b"%d\n\0");
    open.analyse_program().expect("it surveys");
    let mid = open.rendered(BASE + 0x10).expect("it renders");
    let mid = mid.response.output.into_text();
    assert!(mid.starts_with("uint64_t mid("), "{mid}");
    let text = open.rendered(F).expect("it renders");
    let text = text.response.output.into_text();
    assert!(text.starts_with("void f("), "{text}");
}

/// `f`: `sub rsp, 8; add rsp, 8; ret`, which hands back the entry RAX as `_fini` does; no code calls
/// it. 0x1020 is the dynamic table's word naming `f`, and 0x1028 one more data word.
const FINI: &[u8] = &[
    0x48, 0x83, 0xec, 0x08, // 1000 sub rsp, 8
    0x48, 0x83, 0xc4, 0x08, // 1004 add rsp, 8
    0xc3, // 1008 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1009 padding
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, // 1010 padding, or a caller
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1020 DT_FINI's value: f
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1028 a data word
];

/// `f` entered as `kind` from the word at 0x1020, with no symbol beyond its own.
fn entered(kind: r2abi::statement::EntryKind) -> Literal {
    Literal::of_code(FINI, &[("f", BASE, 0x09)])
        .data_mapped_after(BASE + 0x20)
        .text_ending(BASE + 0x20)
        .entering_from(BASE, kind, BASE + 0x20)
}

/// The loader calls `DT_FINI`'s function as an `atexit` handler (r2abi `loader_call`), which reads
/// no result: under `aa` it is `void`, decided by the container's tag, no name (D237).
#[test]
fn a_termination_function_the_loader_alone_calls_is_void() {
    use r2abi::statement::EntryKind;
    let text = analysed(entered(EntryKind::FiniHook));
    assert!(text.starts_with("void f(void)"), "{text}");
    assert!(
        text.contains("; no call reads the result (assuming closed-world)"),
        "{text}"
    );
    // A cold render joins no call, so the entry RAX stays an unproven result.
    let cold = OpenProgram::of(entered(EntryKind::FiniHook))
        .rendered(BASE)
        .expect("it renders");
    let cold = cold.response.output.into_text();
    assert!(cold.contains("return r2sleigh_residual_"), "{cold}");
    // An initialiser has no row: glibc passes it `argc, argv, envp`, and the gABI states no type.
    let init = analysed(entered(EntryKind::InitHook));
    assert!(init.contains("return r2sleigh_residual_"), "{init}");
}

/// The row speaks for the loader's call alone: another word naming `f` is a way in it does not
/// cover, and a call reading the RAX `f` writes makes it a value (D237).
#[test]
fn a_termination_function_another_way_reaches_keeps_its_result() {
    use r2abi::statement::EntryKind;
    let mut stored = entered(EntryKind::FiniHook);
    stored.write(BASE + 0x28, &BASE.to_le_bytes());
    let text = analysed(stored);
    assert!(text.contains("return r2sleigh_residual_"), "{text}");
    // 1000 mov eax, 7; 1005 ret. 1010 call 0x1000; 1015 mov [rdi], rax; 1018 ret
    let mut read = entered(EntryKind::FiniHook).declaring(r2abi::statement::Symbol {
        name: "caller".into(),
        vaddr: BASE + 0x10,
        size: 0x09,
        kind: r2abi::statement::SymbolKind::Function,
        defined: true,
        ..r2abi::statement::Symbol::default()
    });
    read.write(
        BASE,
        &[0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90, 0x90],
    );
    read.write(
        BASE + 0x10,
        &[0xe8, 0xeb, 0xff, 0xff, 0xff, 0x48, 0x89, 0x07, 0xc3],
    );
    let text = analysed(read);
    assert!(text.starts_with("uint32_t f(void)"), "{text}");
    assert!(
        text.contains("; a call reads the result (assuming closed-world)"),
        "{text}"
    );
}

/// `f` is `fld1; ret`: its result is x87 st0, a lane no typed lane covers; `caller` stores st0 and
/// clears xmm0 and xmm1. `void` needs every lane of the return set held: never void (S36, D200).
const X87_WRITTEN: &[u8] = &[
    0xd9, 0xe8, // 1000 fld1
    0xc3, // 1002 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, // 1003 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0xdd, 0x1e, // 1015 fstp qword [rsi]
    0x0f, 0x57, 0xc0, // 1017 xorps xmm0, xmm0
    0x0f, 0x57, 0xc9, // 101a xorps xmm1, xmm1
    0xc3, // 101d ret
    0x90, 0x90,
];

#[test]
fn a_written_x87_result_is_never_void_cold_or_under_the_closed_world() {
    let program = || {
        Literal::of_code(
            X87_WRITTEN,
            &[("f", BASE, 0x03), ("caller", BASE + 0x10, 0x0e)],
        )
    };
    let cold = OpenProgram::of(program())
        .rendered(BASE)
        .expect("it renders");
    let text = cold.response.output.into_text();
    assert!(!text.starts_with("void f("), "{text}");
    // Every typed lane is dead at the one call: before S36 the closed world made this `void`.
    let text = analysed(program());
    assert!(!text.starts_with("void f("), "{text}");
    assert!(text.contains("unproven"), "{text}");
}

/// `f` writes xmm0 and xmm1 (`struct { float a, b, c; }` comes back so); `caller` stores xmm1 and
/// clears eax. No contract states `f`'s result at the call, so the extern is no `void` (S36).
const SECOND_FLOAT_READ: &[u8] = &[
    0x0f, 0x57, 0xc0, // 1000 xorps xmm0, xmm0
    0x0f, 0x57, 0xc9, // 1003 xorps xmm1, xmm1
    0xc3, // 1006 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1007 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0xf3, 0x0f, 0x11, 0x0e, // 1015 movss [rsi], xmm1
    0x31, 0xc0, // 1019 xor eax, eax
    0xc3, // 101b ret
    0x90, 0x90, 0x90, 0x90,
];

#[test]
fn a_call_no_contract_states_declares_no_void_extern() {
    let program = || {
        Literal::of_code(
            SECOND_FLOAT_READ,
            &[("f", BASE, 0x07), ("caller", BASE + 0x10, 0x0c)],
        )
    };
    for analyse in [false, true] {
        let mut open = OpenProgram::of(program());
        if analyse {
            open.analyse_program().expect("it surveys");
        }
        let rendered = open.rendered(BASE + 0x10).expect("it renders");
        let text = rendered.response.output.into_text();
        assert!(text.contains(" f("), "{text}");
        assert!(!text.contains("void f("), "{text}");
    }
}

/// `f` is `push rax; call [rdi]; pop rax; ret`: RAX comes back as it was, XMM0 as the unstated call
/// left it (ldb.clang `p_ldb_forward_b`); `caller` stores XMM0. Never void (S36).
const FORWARDED_UNSTATED_FLOAT: &[u8] = &[
    0x50, // 1000 push rax
    0xff, 0x17, // 1001 call [rdi]
    0x58, // 1003 pop rax
    0xc3, // 1004 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1005 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0xf2, 0x0f, 0x11, 0x06, // 1015 movsd [rsi], xmm0
    0xc3, // 1019 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
];

#[test]
fn a_forwarded_unstated_float_result_is_never_void() {
    let program = || {
        Literal::of_code(
            FORWARDED_UNSTATED_FLOAT,
            &[("f", BASE, 0x05), ("caller", BASE + 0x10, 0x0a)],
        )
    };
    let cold = OpenProgram::of(program())
        .rendered(BASE)
        .expect("it renders");
    let text = cold.response.output.into_text();
    assert!(!text.starts_with("void f("), "{text}");
    let text = analysed(program());
    assert!(!text.starts_with("void f("), "{text}");
}
