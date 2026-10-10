//! A body that hands its own argument register to a call, unwritten, does not prove it takes no
//! argument: prepared alone it cannot see what the call reads.

mod common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;

/// `f`: `call g; mov eax, 1; ret`, handing on the `rdi` it arrived with; `g`: `mov eax, [rdi]; ret`;
/// `caller`: `mov edi, 5; call f; ret`.
const HANDED_ON: &[u8] = &[
    0xe8, 0x0b, 0x00, 0x00, 0x00, // 1000 call 0x1010
    0xb8, 0x01, 0x00, 0x00, 0x00, // 1005 mov eax, 1
    0xc3, // 100a ret
    0x90, 0x90, 0x90, 0x90, 0x90, // 100b padding
    0x8b, 0x07, // 1010 mov eax, [rdi]
    0xc3, // 1012 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1013 padding
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1020 mov edi, 5
    0xe8, 0xd6, 0xff, 0xff, 0xff, // 1025 call 0x1000
    0xc3, // 102a ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 102b padding
];

/// The caller's call to `f` was written `f()`, dropping the 5 `g` reads. `f` hands its `rdi` to `g`
/// unwritten, so `f` is resolved again with `g`, which states what it reads: `f(5)`.
#[test]
fn a_call_to_a_body_that_hands_on_its_argument_passes_it() {
    let text = OpenProgram::of(Literal::of_code(
        HANDED_ON,
        &[
            ("f", BASE, 0x0b),
            ("g", BASE + 0x10, 0x03),
            ("caller", BASE + 0x20, 0x0b),
        ],
    ))
    .rendered(BASE + 0x20)
    .expect("it renders")
    .response
    .output
    .into_text();
    assert!(
        text.contains("f(5)") || text.contains("f((uint64_t)5U)"),
        "{text}"
    );
    assert!(!text.contains("f()"), "{text}");
    assert!(!text.contains("r2sleigh_residual"), "{text}");
}

/// `f` increments `*rdi`, keeps the `rsi` it arrived with in `rbx`, and hands `rbx + 1` to a
/// call through memory, `rdi` as it arrived, and returns 7: the call's arity is unproven at its
/// first slot, so it observes nothing it is handed. `caller`: `mov edi, 3; mov esi, 5; call f`.
const KEPT_FOR_AN_UNPROVEN_CALL: &[u8] = &[
    0x53, // 1000 push rbx
    0x48, 0x89, 0xf3, // 1001 mov rbx, rsi
    0x48, 0x83, 0x07, 0x01, // 1004 add qword [rdi], 1
    0x48, 0x8d, 0x73, 0x01, // 1008 lea rsi, [rbx + 1]
    0xba, 0x07, 0x00, 0x00, 0x00, // 100c mov edx, 7
    0xff, 0x14, 0x25, 0x00, 0x20, 0x00, 0x00, // 1011 call [0x2000]
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1018 mov eax, 7
    0x5b, // 101d pop rbx
    0xc3, // 101e ret
    0xcc, // 101f padding
    0xbf, 0x03, 0x00, 0x00, 0x00, // 1020 mov edi, 3
    0xbe, 0x05, 0x00, 0x00, 0x00, // 1025 mov esi, 5
    0xe8, 0xd1, 0xff, 0xff, 0xff, // 102a call 0x1000
    0xc3, // 102f ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1030 padding
];

/// `f` reads `rsi` only to compute what it hands a call of unproven arity, which no obligation
/// observes: its parameters are a floor, and the caller passes the 5 it wrote.
#[test]
fn a_register_kept_for_a_call_of_unproven_arity_is_passed() {
    let text = OpenProgram::of(Literal::of_code(
        KEPT_FOR_AN_UNPROVEN_CALL,
        &[("f", BASE, 0x1f), ("caller", BASE + 0x20, 0x10)],
    ))
    .rendered(BASE + 0x20)
    .expect("it renders")
    .response
    .output
    .into_text();
    assert!(
        text.contains("f(3, 5)") || text.contains("f((uint64_t)3U, (uint64_t)5U)"),
        "{text}"
    );
}

/// AArch64: `stash` is `str x1, [x0]; ret`, leaving its argument slot x0 untouched (an unproven
/// result); `caller` scrubs x2 (`mov x2, #0`, gcc's canary clear) before only its first call.
const A64_STASH_TWICE: &[u8] = &[
    0x01, 0x00, 0x00, 0xf9, // 1000 str x1, [x0]
    0xc0, 0x03, 0x5f, 0xd6, // 1004 ret
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, // 1008 padding
    0xfd, 0x7b, 0xbe, 0xa9, // 1010 stp x29, x30, [sp, #-32]!
    0xfd, 0x03, 0x00, 0x91, // 1014 mov x29, sp
    0x02, 0x00, 0x80, 0xd2, // 1018 mov x2, #0
    0xe0, 0x43, 0x00, 0x91, // 101c add x0, sp, #16
    0xa1, 0x00, 0x80, 0xd2, // 1020 mov x1, #5
    0xf7, 0xff, 0xff, 0x97, // 1024 bl 0x1000
    0xe0, 0x63, 0x00, 0x91, // 1028 add x0, sp, #24
    0xe1, 0x00, 0x80, 0xd2, // 102c mov x1, #7
    0xf4, 0xff, 0xff, 0x97, // 1030 bl 0x1000
    0xe0, 0x0b, 0x40, 0xf9, // 1034 ldr x0, [sp, #16]
    0xfd, 0x7b, 0xc2, 0xa8, // 1038 ldp x29, x30, [sp], #32
    0xc0, 0x03, 0x5f, 0xd6, // 103c ret
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03,
    0xd5, // 1040 padding
];

/// A callee whose result is unproven still states its parameters, so both calls pass two: counted
/// from what the caller wrote, the scrubbed x2 was a third (aarch64 gcc `shape_call_chain`).
#[test]
fn a_callee_with_an_unproven_result_still_states_its_arity() {
    let text = OpenProgram::of(
        Literal::of_code(
            A64_STASH_TWICE,
            &[("stash", BASE, 0x08), ("caller", BASE + 0x10, 0x30)],
        )
        .in_aarch64(),
    )
    .rendered(BASE + 0x10)
    .expect("it renders")
    .response
    .output
    .into_text();
    assert_eq!(text.matches("stash(").count(), 3, "{text}");
    // No call reads its result, so no return type is claimed for it.
    assert!(text.contains("void stash("), "{text}");
    assert!(!text.contains("r2sleigh_residual"), "{text}");
    assert!(!text.contains(", 0)"), "{text}");
}

/// AArch64: `touch` is `ldr x1, [x0]; add x1, x1, #1; str x1, [x0]; ret`, leaving x0 untouched;
/// `caller` calls it twice in a row, so the second call's argument is the x0 the first one left
/// (gcc's IPA-RA, aarch64 gcc-O2 `shape_struct_pointer`), and then writes w0.
const A64_TOUCH_CHAINED: &[u8] = &[
    0x01, 0x00, 0x40, 0xf9, // 1000 ldr x1, [x0]
    0x21, 0x04, 0x00, 0x91, // 1004 add x1, x1, #1
    0x01, 0x00, 0x00, 0xf9, // 1008 str x1, [x0]
    0xc0, 0x03, 0x5f, 0xd6, // 100c ret
    0xfd, 0x7b, 0xbe, 0xa9, // 1010 stp x29, x30, [sp, #-32]!
    0xfd, 0x03, 0x00, 0x91, // 1014 mov x29, sp
    0xe0, 0x43, 0x00, 0x91, // 1018 add x0, sp, #16
    0xf9, 0xff, 0xff, 0x97, // 101c bl 0x1000
    0xf8, 0xff, 0xff, 0x97, // 1020 bl 0x1000
    0x60, 0x00, 0x80, 0x52, // 1024 mov w0, #3
    0xfd, 0x7b, 0xc2, 0xa8, // 1028 ldp x29, x30, [sp], #32
    0xc0, 0x03, 0x5f, 0xd6, // 102c ret
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03,
    0xd5, // 1030 padding
];

/// One prototype holds at every call to a callee: the first call's result may be read past its
/// block (the second call's argument), so neither call is a statement of a `void` callee.
#[test]
fn a_result_one_call_may_read_is_no_call_s_void() {
    let text = OpenProgram::of(
        Literal::of_code(
            A64_TOUCH_CHAINED,
            &[("touch", BASE, 0x10), ("caller", BASE + 0x10, 0x20)],
        )
        .in_aarch64(),
    )
    .rendered(BASE + 0x10)
    .expect("it renders")
    .response
    .output
    .into_text();
    assert_eq!(text.matches("touch(").count(), 3, "{text}");
    assert!(!text.contains("void touch("), "{text}");
    assert!(!text.contains("r2sleigh_residual"), "{text}");
}
