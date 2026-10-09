//! A body that writes both result registers returns the one its callers read
//! (doc/adr-resolved-bodies.md, "Caller reads").

mod common;

use common::{BASE, Literal};
use r2engine::RenderTier;
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

fn rendered(program: Literal, tier: RenderTier) -> String {
    OpenProgram::of(program)
        .rendered(BASE, tier)
        .expect("it renders")
        .response
        .output
        .into_text()
}

#[test]
fn a_caller_reading_the_integer_register_decides_the_result() {
    let program = || {
        Literal::of_code(
            READ_AS_INTEGER,
            &[("f", BASE, 0x0a), ("caller", BASE + 0x10, 0x08)],
        )
    };
    for tier in [RenderTier::C, RenderTier::Staged] {
        let text = rendered(program(), tier);
        assert!(text.starts_with("uint64_t f("), "{tier:?}: {text}");
        assert!(text.contains("7"), "{tier:?}: {text}");
        assert!(!text.contains("r2sleigh_residual"), "{tier:?}: {text}");
    }
}

/// The same body with no call to it: nothing says which register is its result.
#[test]
fn without_a_reading_call_the_result_stays_a_residual() {
    let program = || Literal::of_code(READ_AS_INTEGER, &[("f", BASE, 0x0a)]);
    for tier in [RenderTier::C, RenderTier::Staged] {
        let text = rendered(program(), tier);
        assert!(
            text.contains("return r2sleigh_residual_"),
            "{tier:?}: {text}"
        );
    }
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
/// `double`: the caller declares it so. Uncertified, the declaration was `void` beside an assigned
/// result, which no C compiler accepts.
#[test]
fn a_float_result_reloaded_from_the_frame_is_declared_at_its_type() {
    let program = Literal::of_code(
        RELOADED_DOUBLE,
        &[("first", BASE, 0x2b), ("caller", BASE + 0x30, 0x0a)],
    );
    let text = OpenProgram::of(program)
        .rendered(BASE + 0x30, RenderTier::C)
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

/// AArch64's float result slot is all of q0; the double the caller reads is d0, the lane a
/// declared double returns in. Typed at q0, the return was never certified, and a caller's
/// legacy rendering declared `f` `void` beside the result it assigned, which no compiler accepts.
#[test]
fn an_aarch64_float_result_is_its_lane() {
    let program = Literal::of_code(
        A64_READ_AS_DOUBLE,
        &[("f", BASE, 0x0c), ("caller", BASE + 0x10, 0x0c)],
    )
    .in_aarch64();
    let text = OpenProgram::of(program)
        .rendered(BASE + 0x10, RenderTier::C)
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
    let text = rendered(program, RenderTier::C);
    assert!(text.contains("double f("), "{text}");
    assert!(
        text.contains("return r2sleigh_float_from_bits_64(r2sleigh_bits_extract_256_64("),
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
    for tier in [RenderTier::C, RenderTier::Staged] {
        let render = |at| {
            OpenProgram::of(program())
                .rendered(at, tier)
                .expect("it renders")
                .response
                .output
                .into_text()
        };
        let (a, b, f) = (render(BASE + 0x10), render(BASE + 0x20), render(BASE));
        assert!(a.contains("uint64_t f(void);"), "{tier:?}: {a}");
        assert!(b.contains("double f(void);"), "{tier:?}: {b}");
        assert!(f.contains("return r2sleigh_residual_u64("), "{tier:?}: {f}");
    }
}
