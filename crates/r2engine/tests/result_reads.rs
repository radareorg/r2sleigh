//! A body that writes both result registers returns the one its callers read
//! (doc/adr-resolved-bodies.md, "Caller reads").

mod common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;

/// `pxor xmm0, xmm0; mov eax, 7; ret`, as vectorized integer code leaves XMM0 written, then
/// `call f; mov [rsi], eax; ret`, which reads EAX as the call left it.
const READ_AS_INTEGER: &[u8] = &[
    0x66, 0x0f, 0xef, 0xc0, // 1000 pxor xmm0, xmm0
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1004 mov eax, 7
    0xc3, // 1009 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 100a padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x89, 0x06, // 1015 mov [rsi], eax
    0xc3, // 1017 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1018 padding
];

/// `f` rendered after `aa`, which reads its callers.
fn rendered(program: Literal) -> String {
    let mut open = OpenProgram::of(program);
    open.analyse_program().expect("it surveys");
    fresh(open)
}

/// `f` rendered from its own body and callees: a fresh open, or one before `aa`.
fn fresh(mut open: OpenProgram<Literal>) -> String {
    let rendering = open.rendered(BASE).expect("it renders");
    rendering.response.output.into_text()
}

#[test]
fn a_caller_reading_the_integer_register_decides_the_result() {
    let program = || {
        Literal::of_code(
            READ_AS_INTEGER,
            &[("f", BASE, 0x0a), ("caller", BASE + 0x10, 0x08)],
        )
    };
    let text = rendered(program());
    assert!(text.starts_with("uint64_t f("), "{text}");
    assert!(text.contains("7"), "{text}");
    assert!(!text.contains("r2sleigh_residual"), "{text}");
}

/// Before `aa`, the calls are not read: a fresh open renders the body alone, whose result stays
/// open, and `aa` decides it in the same session.
#[test]
fn before_aa_a_function_reads_no_callers() {
    let functions = [("f", BASE, 0x0a), ("caller", BASE + 0x10, 0x08)];
    let mut open = OpenProgram::of(Literal::of_code(READ_AS_INTEGER, &functions));
    let before = open
        .rendered(BASE)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(before.contains("return r2sleigh_residual_"), "{before}");
    open.analyse_program().expect("it surveys");
    assert_eq!(
        rendered(Literal::of_code(READ_AS_INTEGER, &functions)),
        fresh(open)
    );
}

/// The same body with no call to it: nothing says which register is its result.
#[test]
fn without_a_reading_call_the_result_stays_a_residual() {
    let program = || Literal::of_code(READ_AS_INTEGER, &[("f", BASE, 0x0a)]);
    let text = rendered(program());
    assert!(text.contains("return r2sleigh_residual_"), "{text}");
}

/// clang -O0's `double first(double *v)`: RAX holds the loaded pointer, and XMM0 the result reloaded
/// from the frame slot two paths stored it to; the caller stores it with `movsd [rsi], xmm0`.
const RELOADED_DOUBLE: &[u8] = &[
    0x55, // 1000 push rbp
    0x48, 0x89, 0xe5, // 1001 mov rbp, rsp
    0x48, 0x89, 0x7d, 0xf0, // 1004 mov [rbp - 16], rdi
    0x48, 0x8b, 0x45, 0xf0, // 1008 mov rax, [rbp - 16]
    0xf2, 0x0f, 0x10, 0x00, // 100c movsd xmm0, [rax]
    0xf2, 0x0f, 0x11, 0x45, 0xf8, // 1010 movsd [rbp - 8], xmm0
    0x48, 0x85, 0xff, // 1015 test rdi, rdi
    0x74, 0x0a, // 1018 je 0x1024
    0xf2, 0x0f, 0x10, 0x40, 0x08, // 101a movsd xmm0, [rax + 8]
    0xf2, 0x0f, 0x11, 0x45, 0xf8, // 101f movsd [rbp - 8], xmm0
    0xf2, 0x0f, 0x10, 0x45, 0xf8, // 1024 movsd xmm0, [rbp - 8]
    0x5d, // 1029 pop rbp
    0xc3, // 102a ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 102b padding
    0xe8, 0xcb, 0xff, 0xff, 0xff, // 1030 call 0x1000
    0xf2, 0x0f, 0x11, 0x06, // 1035 movsd [rsi], xmm0
    0xc3, // 1039 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 103a padding
];

/// The caller's read makes `first` a `double`, and the reload from its promoted frame slot is that
/// `double`; uncertified, `first` was declared `void` beside an assigned result.
#[test]
fn a_float_result_reloaded_from_the_frame_is_declared_at_its_type() {
    let program = Literal::of_code(
        RELOADED_DOUBLE,
        &[("first", BASE, 0x2b), ("caller", BASE + 0x30, 0x0a)],
    );
    let text = OpenProgram::of(program)
        .rendered(BASE + 0x30)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(text.contains("double first("), "{text}");
    assert!(!text.contains("void first("), "{text}");
}

/// AArch64: `f` is `mov x0, #7; fmov d0, #1.0; ret`, and `caller` is `bl f; str d0, [x1]; ret`.
const A64_READ_AS_DOUBLE: &[u8] = &[
    0xe0, 0x00, 0x80, 0xd2, // 1000 mov x0, #7
    0x00, 0x10, 0x6e, 0x1e, // 1004 fmov d0, #1.0
    0xc0, 0x03, 0x5f, 0xd6, // 1008 ret
    0x1f, 0x20, 0x03, 0xd5, // 100c nop
    0xfc, 0xff, 0xff, 0x97, // 1010 bl 0x1000
    0x20, 0x00, 0x00, 0xfd, // 1014 str d0, [x1]
    0xc0, 0x03, 0x5f, 0xd6, // 1018 ret
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03,
    0xd5, // 101c padding
];

/// AArch64's float result slot is all of q0; the double the caller reads is its d0 lane. Typed at
/// q0 the return was never certified, and legacy declared `f` `void` beside an assigned result.
#[test]
fn an_aarch64_float_result_is_its_lane() {
    let program = Literal::of_code(
        A64_READ_AS_DOUBLE,
        &[("f", BASE, 0x0c), ("caller", BASE + 0x10, 0x0c)],
    )
    .in_aarch64();
    let text = OpenProgram::of(program)
        .rendered(BASE + 0x10)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(text.contains("double f("), "{text}");
    assert!(!text.contains("void f("), "{text}");
}

/// AArch64: `f` is `cbz x0, 1f; fmov d0, #1.0; b 2f; 1: movi d0, #0; 2: mov x0, #7; ret`, and
/// `caller` is `bl f; str d0, [x1]; ret`. Each write of d0 lifts to a write of the whole Z register.
const A64_MERGED_DOUBLE: &[u8] = &[
    0x60, 0x00, 0x00, 0xb4, // 1000 cbz x0, 0x100c
    0x00, 0x10, 0x6e, 0x1e, // 1004 fmov d0, #1.0
    0x02, 0x00, 0x00, 0x14, // 1008 b 0x1010
    0x00, 0xe4, 0x00, 0x2f, // 100c movi d0, #0
    0xe0, 0x00, 0x80, 0xd2, // 1010 mov x0, #7
    0xc0, 0x03, 0x5f, 0xd6, // 1014 ret
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, // 1018 padding
    0xf8, 0xff, 0xff, 0x97, // 1020 bl 0x1000
    0x20, 0x00, 0x00, 0xfd, // 1024 str d0, [x1]
    0xc0, 0x03, 0x5f, 0xd6, // 1028 ret
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03,
    0xd5, // 102c padding
];

/// The double `f` returns is the low lane of the Z register both paths write; returned whole, the
/// struct carrier was no `double`, and the C did not compile.
#[test]
fn an_aarch64_float_merged_in_its_vector_register_returns_its_lane() {
    let program = Literal::of_code(
        A64_MERGED_DOUBLE,
        &[("f", BASE, 0x18), ("caller", BASE + 0x20, 0x0c)],
    )
    .in_aarch64();
    let text = rendered(program);
    assert!(text.contains("double f("), "{text}");
    let body = &text[text.find("double f(").expect("the definition")..];
    let returned = body
        .lines()
        .find(|line| line.trim_start().starts_with("return "))
        .expect("a return");
    assert!(
        returned.contains("r2sleigh_float_from_bits_64(r2sleigh_bits_extract_256_64("),
        "{text}"
    );
}

/// `f` as above, `caller_a`: `call f; mov [rsi], eax; ret`, `caller_b`: `call f; movsd [rsi], xmm0; ret`.
const READ_TWO_WAYS: &[u8] = &[
    0x66, 0x0f, 0xef, 0xc0, // 1000 pxor xmm0, xmm0
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1004 mov eax, 7
    0xc3, // 1009 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 100a padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x89, 0x06, // 1015 mov [rsi], eax
    0xc3, // 1017 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1018 padding
    0xe8, 0xdb, 0xff, 0xff, 0xff, // 1020 call 0x1000
    0xf2, 0x0f, 0x11, 0x06, // 1025 movsd [rsi], xmm0
    0xc3, // 1029 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 102a padding
];

/// The program's calls disagree, so `f` itself proves no result; each call still takes the register
/// its own caller reads, decided from that caller's code alone.
#[test]
fn each_call_takes_the_register_its_caller_reads() {
    let program = || {
        Literal::of_code(
            READ_TWO_WAYS,
            &[
                ("f", BASE, 0x0a),
                ("caller_a", BASE + 0x10, 0x08),
                ("caller_b", BASE + 0x20, 0x0a),
            ],
        )
    };
    let render = |at| {
        OpenProgram::of(program())
            .rendered(at)
            .expect("it renders")
            .response
            .output
            .into_text()
    };
    let (a, b, f) = (render(BASE + 0x10), render(BASE + 0x20), render(BASE));
    assert!(a.contains("uint64_t f(void);"), "{a}");
    assert!(b.contains("double f(void);"), "{b}");
    assert!(f.contains("return r2sleigh_residual_u64("), "{f}");
}

/// `f` as above, `caller_a`: `call f; movss [rsi], xmm0; ret`, `caller_b`: `call f; movsd [rsi], xmm0; ret`.
const READ_AT_TWO_WIDTHS: &[u8] = &[
    0x66, 0x0f, 0xef, 0xc0, // 1000 pxor xmm0, xmm0
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1004 mov eax, 7
    0xc3, // 1009 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 100a padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0xf3, 0x0f, 0x11, 0x06, // 1015 movss [rsi], xmm0
    0xc3, // 1019 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 101a padding
    0xe8, 0xdb, 0xff, 0xff, 0xff, // 1020 call 0x1000
    0xf2, 0x0f, 0x11, 0x06, // 1025 movsd [rsi], xmm0
    0xc3, // 1029 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 102a padding
];

/// The calls read XMM0 as a `float` and as a `double`: no one width is the result, so `f` proves
/// none, where the widest read made it a `double` beside a call that reads a `float`.
#[test]
fn float_reads_at_two_widths_prove_no_result() {
    let program = || {
        Literal::of_code(
            READ_AT_TWO_WIDTHS,
            &[
                ("f", BASE, 0x0a),
                ("caller_a", BASE + 0x10, 0x0a),
                ("caller_b", BASE + 0x20, 0x0a),
            ],
        )
    };
    let f = rendered(program());
    assert!(!f.starts_with("double f("), "{f}");
    assert!(f.contains("return r2sleigh_residual_"), "{f}");
}

/// `f(x)` is `pxor xmm0, xmm0; mov rax, rdi; ret`; `caller_a`: `call f; mov [rsi], eax; ret`,
/// `caller_b`: `call f; movsd [rsi], xmm0; ret`.
const TAKES_ONE_READ_TWO_WAYS: &[u8] = &[
    0x66, 0x0f, 0xef, 0xc0, // 1000 pxor xmm0, xmm0
    0x48, 0x89, 0xf8, // 1004 mov rax, rdi
    0xc3, // 1007 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1008 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x89, 0x06, // 1015 mov [rsi], eax
    0xc3, // 1017 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1018 padding
    0xe8, 0xdb, 0xff, 0xff, 0xff, // 1020 call 0x1000
    0xf2, 0x0f, 0x11, 0x06, // 1025 movsd [rsi], xmm0
    0xc3, // 1029 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 102a padding
];

/// `f` proves no result, so its callers declare it with the parameter type its own header states
/// and no other: an unauthorized merged signature is never what they are handed.
#[test]
fn callers_declare_a_two_carrier_body_as_its_header_does() {
    let program = || {
        Literal::of_code(
            TAKES_ONE_READ_TWO_WAYS,
            &[
                ("f", BASE, 0x08),
                ("caller_a", BASE + 0x10, 0x08),
                ("caller_b", BASE + 0x20, 0x0a),
            ],
        )
    };
    let f = rendered(program());
    assert!(f.contains("return r2sleigh_residual_u64("), "{f}");
    let header = f.lines().next().expect("a header");
    let (_, parameter) = header.split_once("f(").expect("f's header");
    let (ty, _) = parameter.rsplit_once(' ').expect("one named parameter");
    for at in [BASE + 0x10, BASE + 0x20] {
        let caller = OpenProgram::of(program())
            .rendered(at)
            .expect("it renders")
            .response
            .output
            .into_text();
        assert!(caller.contains(&format!(" f({ty});")), "{f}\n{caller}");
    }
}

/// clang's `double avg(...)` shape: `cvtsi2sd xmm0, edi; ret` writes only XMM0 and leaves RAX as
/// the caller left it, and the caller stores XMM0 with `movsd [rsi], xmm0`.
const ONLY_XMM0_WRITTEN: &[u8] = &[
    0xf2, 0x0f, 0x2a, 0xc7, // 1000 cvtsi2sd xmm0, edi
    0xc3, // 1004 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1005 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0xf2, 0x0f, 0x11, 0x06, // 1015 movsd [rsi], xmm0
    0xc3, // 1019 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 101a padding
];

/// RAX handed back as the caller left it is no result where every reading call reads XMM0: the
/// float register is, at the width the reads take. With no call, nothing says so.
#[test]
fn a_float_result_beside_an_untouched_integer_register_is_the_one_callers_read() {
    let program =
        |functions: &[(&'static str, u64, u64)]| Literal::of_code(ONLY_XMM0_WRITTEN, functions);
    let text = rendered(program(&[("f", BASE, 5), ("caller", BASE + 0x10, 0x0a)]));
    assert!(text.starts_with("double f("), "{text}");
    assert!(!text.contains("r2sleigh_residual"), "{text}");
    let unread = rendered(program(&[("f", BASE, 5)]));
    assert!(unread.contains("return r2sleigh_residual_"), "{unread}");
}

/// AArch64's `uint8_t narrow8(int q) { return q; }` at -O1 is a bare `ret`: x0 is both the argument
/// and the result, and `caller` is `bl f; str w0, [x1]; ret`.
const A64_RETURNS_ITS_ARGUMENT: &[u8] = &[
    0xc0, 0x03, 0x5f, 0xd6, // 1000 ret
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, // 1004 padding
    0xfc, 0xff, 0xff, 0x97, // 1010 bl 0x1000
    0x20, 0x00, 0x00, 0xb9, // 1014 str w0, [x1]
    0xc0, 0x03, 0x5f, 0xd6, // 1018 ret
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03,
    0xd5, // 101c padding
];

/// An argument register handed back untouched is the result where every reading call reads it, and
/// the return reads it as the parameter it is. With no call, nothing says so.
#[test]
fn an_argument_register_handed_back_untouched_is_the_result_callers_read() {
    let program = |functions: &[(&'static str, u64, u64)]| {
        Literal::of_code(A64_RETURNS_ITS_ARGUMENT, functions).in_aarch64()
    };
    let text = rendered(program(&[("f", BASE, 4), ("caller", BASE + 0x10, 0x0c)]));
    assert!(text.contains("return (uint64_t)arg0;"), "{text}");
    assert!(!text.contains("r2sleigh_residual"), "{text}");
    let unread = rendered(program(&[("f", BASE, 4)]));
    assert!(unread.contains("r2sleigh_residual_"), "{unread}");
}

/// `mov rax, rdi; mov rdx, rsi; ret`, a 16-byte value returned in RDX:RAX, then
/// `call f; mov rax, rdx; ret`, which reads the high half and returns it.
const PAIR: &[u8] = &[
    0x48, 0x89, 0xf8, // 1000 mov rax, rdi
    0x48, 0x89, 0xf2, // 1003 mov rdx, rsi
    0xc3, // 1006 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1007 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x48, 0x89, 0xd0, // 1015 mov rax, rdx
    0xc3, // 1018 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1019 padding
];

/// A body that writes both result registers on every return, called by code that reads the second,
/// returns one 128-bit value; the caller reads its high half. With no call, it returns RAX alone.
#[test]
fn a_value_in_two_registers_is_one_result_where_callers_read_the_second() {
    let program = |functions: &[(&'static str, u64, u64)]| Literal::of_code(PAIR, functions);
    let both = [("f", BASE, 7), ("caller", BASE + 0x10, 9)];
    let f = rendered(program(&both));
    let caller = OpenProgram::of(program(&both))
        .rendered(BASE + 0x10)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(f.starts_with("__uint128_t f("), "{f}");
    assert!(f.contains("<< 64U"), "the high half above the low: {f}");
    assert!(!f.contains("r2sleigh_residual"), "{f}");
    assert!(
        caller.contains("__uint128_t f(uint64_t, uint64_t);"),
        "{caller}"
    );
    assert!(
        caller.contains(">> 64U"),
        "the high half read from the pair: {caller}"
    );
    assert!(!caller.contains("r2sleigh_residual"), "{caller}");
    let open = "the result's second register is open";
    assert!(!f.contains(open), "{f}");
    let alone = rendered(program(&[("f", BASE, 7)]));
    assert!(alone.starts_with("uint64_t f("), "{alone}");
    assert!(
        alone.contains(open),
        "no call read decides the high half: {alone}"
    );
    // Before `aa`, the calls are not read: the low half alone, and the high half is open.
    let unread = fresh(OpenProgram::of(program(&both)));
    assert!(unread.starts_with("uint64_t f("), "{unread}");
    assert!(unread.contains(open), "{unread}");
}

/// `mov rax, rdi; xor edx, edx; ret` writes RDX on every return, and `call f; ret` reads only RAX:
/// the result stays the one register, and the caller is unchanged.
const SCRATCH_SECOND: &[u8] = &[
    0x48, 0x89, 0xf8, // 1000 mov rax, rdi
    0x31, 0xd2, // 1003 xor edx, edx
    0xc3, // 1005 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1006 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0xc3, // 1015 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1016 padding
];

#[test]
fn a_second_register_no_caller_reads_is_no_half_of_the_result() {
    let functions = [("f", BASE, 6), ("caller", BASE + 0x10, 6)];
    let f = rendered(Literal::of_code(SCRATCH_SECOND, &functions));
    assert!(f.starts_with("uint64_t f("), "{f}");
    assert!(!f.contains("__uint128_t"), "{f}");
    let caller = OpenProgram::of(Literal::of_code(SCRATCH_SECOND, &functions))
        .rendered(BASE + 0x10)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(!caller.contains("__uint128_t"), "{caller}");
    assert!(!caller.contains("r2sleigh_residual"), "{caller}");
}

/// AArch64: `f` is `add x1, x0, #2; add x0, x0, #1; ret`, a value in X1:X0, and `caller` is
/// `bl f; mov x0, x1; ret`, which returns the high half.
const A64_PAIR: &[u8] = &[
    0x01, 0x08, 0x00, 0x91, // 1000 add x1, x0, #2
    0x00, 0x04, 0x00, 0x91, // 1004 add x0, x0, #1
    0xc0, 0x03, 0x5f, 0xd6, // 1008 ret
    0x1f, 0x20, 0x03, 0xd5, // 100c nop
    0xfc, 0xff, 0xff, 0x97, // 1010 bl 0x1000
    0xe0, 0x03, 0x01, 0xaa, // 1014 mov x0, x1
    0xc0, 0x03, 0x5f, 0xd6, // 1018 ret
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03,
    0xd5, // 101c padding
];

#[test]
fn an_aarch64_value_in_x1_x0_is_one_result_where_callers_read_x1() {
    let functions = [("f", BASE, 0x0c), ("caller", BASE + 0x10, 0x0c)];
    let program = || Literal::of_code(A64_PAIR, &functions).in_aarch64();
    let f = rendered(program());
    assert!(f.starts_with("__uint128_t f("), "{f}");
    assert!(!f.contains("r2sleigh_residual"), "{f}");
    let caller = OpenProgram::of(program())
        .rendered(BASE + 0x10)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(caller.contains(">> 64U"), "{caller}");
    assert!(!caller.contains("r2sleigh_residual"), "{caller}");
}

/// `f` is `call g; ret`, and its call takes `g`'s EAX alone: RDX at `f`'s return is what `g` left
/// there, no value of `f`'s, so a caller reading RDX after `f` makes no pair of it.
const CLOBBERED_SECOND: &[u8] = &[
    0xe8, 0x1b, 0x00, 0x00, 0x00, // 1000 call 0x1020
    0xc3, // 1005 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1006 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x48, 0x89, 0xd0, // 1015 mov rax, rdx
    0xc3, // 1018 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1019 padding
    0x31, 0xd2, // 1020 xor edx, edx
    0xb8, 0x01, 0x00, 0x00, 0x00, // 1022 mov eax, 1
    0xc3, // 1027 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1028 padding
];

#[test]
fn a_register_a_callee_left_is_no_half_of_the_result() {
    let functions = [
        ("f", BASE, 6),
        ("caller", BASE + 0x10, 9),
        ("g", BASE + 0x20, 8),
    ];
    let f = rendered(Literal::of_code(CLOBBERED_SECOND, &functions));
    assert!(!f.contains("__uint128_t"), "{f}");
    assert!(!f.contains("second register is open"), "{f}");
}

/// `test rdi, rdi; sete dl; mov rax, rdi; ret`: DL over the caller's other seven bytes of RDX, as
/// clang -O1's `table_walk` leaves it. A caller reading RDX after `f` makes no half of it.
const BYTE_OVER_THE_CALLERS: &[u8] = &[
    0x48, 0x85, 0xff, // 1000 test rdi, rdi
    0x0f, 0x94, 0xc2, // 1003 sete dl
    0x48, 0x89, 0xf8, // 1006 mov rax, rdi
    0xc3, // 1009 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 100a padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x48, 0x89, 0xd0, // 1015 mov rax, rdx
    0xc3, // 1018 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1019 padding
];

#[test]
fn a_byte_written_over_the_callers_register_is_no_half_of_the_result() {
    let functions = [("f", BASE, 0x0a), ("caller", BASE + 0x10, 9)];
    let f = rendered(Literal::of_code(BYTE_OVER_THE_CALLERS, &functions));
    assert!(f.starts_with("uint64_t f(uint64_t arg0)"), "{f}");
    assert!(!f.contains("second register is open"), "{f}");
}

/// `f` returns in RDX:RAX, and `caller` reaches it through a register the instruction before loads:
/// `lea rax, [rip + f]; call rax; mov rax, rdx; ret`.
const FOLDED_PAIR: &[u8] = &[
    0x48, 0x89, 0xf8, // 1000 mov rax, rdi
    0x48, 0x89, 0xf2, // 1003 mov rdx, rsi
    0xc3, // 1006 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1007 padding
    0x48, 0x8d, 0x05, 0xe9, 0xff, 0xff, 0xff, // 1010 lea rax, [rip - 0x17]
    0xff, 0xd0, // 1017 call rax
    0x48, 0x89, 0xd0, // 1019 mov rax, rdx
    0xc3, // 101c ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 101d padding
];

#[test]
fn a_call_the_walk_folds_is_a_call_whose_reads_count() {
    let functions = [("f", BASE, 7), ("caller", BASE + 0x10, 0x0d)];
    let f = rendered(Literal::of_code(FOLDED_PAIR, &functions));
    assert!(f.starts_with("__uint128_t f("), "{f}");
    let caller = OpenProgram::of(Literal::of_code(FOLDED_PAIR, &functions))
        .rendered(BASE + 0x10)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(caller.contains(">> 64U"), "{caller}");
    assert!(!caller.contains("r2sleigh_residual"), "{caller}");
}
