//! A result lane holds a value only where a C expression defines a byte a return leaves
//! (doc/adr-scratch-result.md, D200), and an unproven result claims none (D201).

use crate::common;

use common::{Literal, PLT_CALLER, plt_then};
use r2engine::program::OpenProgram;

fn rendered(literal: Literal, at: u64) -> String {
    OpenProgram::of(literal)
        .rendered(at)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// The first line that declares the function: its header.
fn header(text: &str) -> &str {
    let at = format!("fcn_{PLT_CALLER:x}(");
    text.lines()
        .find(|line| line.contains(&at) && !line.trim_start().starts_with("/*"))
        .expect("a header")
}

/// gcc's stack protector around `puts`: the check leaves `reload - guard` in RAX at the return,
/// and `puts` overwrites XMM0. `halt` at 0x1060 never returns.
const CANARY_VOID: [u8; 0x62] = plt_then(&[
    0x48, 0x83, 0xec, 0x18, // 1020 sub rsp, 0x18
    0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, // 1024 mov rax, fs:[0x28]
    0x48, 0x89, 0x44, 0x24, 0x08, // 102d mov [rsp + 8], rax
    0x31, 0xc0, // 1032 xor eax, eax
    0xe8, 0xd7, 0xff, 0xff, 0xff, // 1034 call stub (puts)
    0x48, 0x8b, 0x44, 0x24, 0x08, // 1039 mov rax, [rsp + 8]
    0x64, 0x48, 0x2b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, // 103e sub rax, fs:[0x28]
    0x75, 0x05, // 1047 jne 0x104e
    0x48, 0x83, 0xc4, 0x18, // 1049 add rsp, 0x18
    0xc3, // 104d ret
    0xe8, 0x0d, 0x00, 0x00, 0x00, // 104e call 0x1060
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1053
    0xeb, 0xfe, // 1060 jmp 0x1060
]);

#[test]
fn the_canary_left_in_the_result_register_is_no_result() {
    let text = rendered(Literal::plt_wrapped("puts", &CANARY_VOID), PLT_CALLER);
    assert!(header(&text).starts_with("void "), "{text}");
    assert!(!text.contains("return 0;"), "{text}");
}

/// gcc 13.3 `-O2 -fstack-protector-all`, `r = 0; b[0] = 1; if (*s) r = s[1]; return r;`: the scrub
/// after the guard store is also `r = 0`, and the check runs in RDX (result-side ADR, S24 as built).
const SCRUB_RETURNED: [u8; 0x62] = plt_then(&[
    0x48, 0x83, 0xec, 0x18, // 1020 sub rsp, 0x18
    0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, // 1024 mov rax, fs:[0x28]
    0x48, 0x89, 0x44, 0x24, 0x08, // 102d mov [rsp + 8], rax
    0x31, 0xc0, // 1032 xor eax, eax
    0x80, 0x3f, 0x00, // 1034 cmp byte [rdi], 0
    0xc6, 0x04, 0x24, 0x01, // 1037 mov byte [rsp], 1
    0x74, 0x04, // 103b je 0x1041
    0x0f, 0xb6, 0x47, 0x01, // 103d movzx eax, byte [rdi + 1]
    0x48, 0x8b, 0x54, 0x24, 0x08, // 1041 mov rdx, [rsp + 8]
    0x64, 0x48, 0x2b, 0x14, 0x25, 0x28, 0x00, 0x00, 0x00, // 1046 sub rdx, fs:[0x28]
    0x75, 0x05, // 104f jne 0x1056
    0x48, 0x83, 0xc4, 0x18, // 1051 add rsp, 0x18
    0xc3, // 1055 ret
    0xe8, 0x05, 0x00, 0x00, 0x00, // 1056 call 0x1060
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 105b
    0xeb, 0xfe, // 1060 jmp 0x1060
]);

/// The scrub after the guard store is no compiler-inserted write where gcc merges it with a C
/// zero (G19, refused): the path that skips the load returns that zero, a value.
#[test]
fn a_guard_scrub_a_return_reads_is_the_returned_zero() {
    let text = rendered(Literal::plt_wrapped("puts", &SCRUB_RETURNED), PLT_CALLER);
    assert!(!header(&text).starts_with("void "), "{text}");
    assert!(!text.contains("r2sleigh_residual"), "{text}");
}

/// gcc's cold part of pigz `alloc` (`0x4044b0`): the body's one way out is a call that never comes
/// back. `halt` at 0x1060 never returns.
const NEVER_RETURNS: [u8; 0x62] = plt_then(&[
    0x48, 0x83, 0xec, 0x08, // 1020 sub rsp, 8
    0xe8, 0x37, 0x00, 0x00, 0x00, // 1024 call 0x1060
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1029
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1039
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1049
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1059
    0xeb, 0xfe, // 1060 jmp 0x1060
]);

/// No return path leaves no lane a `void` could be read from (D74's silent void): the header is
/// the carrier word, and the proof line says no return is reached.
#[test]
fn a_body_no_return_path_leaves_is_never_void() {
    let text = rendered(Literal::plt_wrapped("puts", &NEVER_RETURNS), PLT_CALLER);
    assert!(header(&text).starts_with("r2sleigh_result_u64 "), "{text}");
    assert!(
        text.contains("the result is unproven (no return reached)"),
        "{text}"
    );
    assert!(text.contains("fcn_1060();"), "{text}");
}

/// The same check in RAX, with `puts`' result kept in RBX and moved back after it.
const CANARY_KEEPS: [u8; 0x62] = plt_then(&[
    0x53, // 1020 push rbx
    0x48, 0x83, 0xec, 0x10, // 1021 sub rsp, 0x10
    0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, // 1025 mov rax, fs:[0x28]
    0x48, 0x89, 0x44, 0x24, 0x08, // 102e mov [rsp + 8], rax
    0x31, 0xc0, // 1033 xor eax, eax
    0xe8, 0xd6, 0xff, 0xff, 0xff, // 1035 call stub (puts)
    0x89, 0xc3, // 103a mov ebx, eax
    0x48, 0x8b, 0x44, 0x24, 0x08, // 103c mov rax, [rsp + 8]
    0x64, 0x48, 0x2b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, // 1041 sub rax, fs:[0x28]
    0x75, 0x08, // 104a jne 0x1054
    0x89, 0xd8, // 104c mov eax, ebx
    0x48, 0x83, 0xc4, 0x10, // 104e add rsp, 0x10
    0x5b, // 1052 pop rbx
    0xc3, // 1053 ret
    0xe8, 0x07, 0x00, 0x00, 0x00, // 1054 call 0x1060
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1059
    0xeb, 0xfe, // 1060 jmp 0x1060
]);

#[test]
fn a_canary_function_returning_a_kept_value_is_unproven_not_void() {
    let text = rendered(Literal::plt_wrapped("puts", &CANARY_KEEPS), PLT_CALLER);
    assert!(header(&text).starts_with("r2sleigh_result_u32 "), "{text}");
    assert!(text.contains("the result is unproven (Written)"), "{text}");
    assert!(text.contains("return r2sleigh_carrier_u32("), "{text}");
}

/// `safe_atoi`'s shape: one path returns `3 * k`, the other calls `free` and falls off the end.
const SOME_PATH: [u8; 0x36] = plt_then(&[
    0x85, 0xff, // 1020 test edi, edi
    0x74, 0x04, // 1022 je 0x1028
    0x8d, 0x04, 0x7f, // 1024 lea eax, [rdi + rdi*2]
    0xc3, // 1027 ret
    0x48, 0x83, 0xec, 0x08, // 1028 sub rsp, 8
    0xe8, 0xdf, 0xff, 0xff, 0xff, // 102c call stub (free)
    0x48, 0x83, 0xc4, 0x08, // 1031 add rsp, 8
    0xc3, // 1035 ret
]);

#[test]
fn a_value_on_one_path_beside_a_void_call_is_written_not_void() {
    let text = rendered(Literal::plt_wrapped("free", &SOME_PATH), PLT_CALLER);
    assert!(!header(&text).starts_with("void "), "{text}");
    assert!(text.contains("the result is unproven (Written)"), "{text}");
}

/// A body that reads AL on entry (a variadic prologue's vector count): RAX's entry byte is an input.
const READS_AL: [u8; 0x26] = plt_then(&[
    0x84, 0xc0, // 1020 test al, al
    0x0f, 0x95, 0x07, // 1022 setne [rdi]
    0xc3, // 1025 ret
]);

#[test]
fn a_body_reading_al_on_entry_is_never_void() {
    let text = rendered(Literal::plt_wrapped("free", &READS_AL), PLT_CALLER);
    assert!(!header(&text).starts_with("void "), "{text}");
    assert!(
        text.contains("the result is unproven (EntryInput)"),
        "{text}"
    );
}

#[test]
fn a_tail_jump_to_free_is_void() {
    let text = rendered(Literal::plt_forwarding_to("free"), PLT_CALLER);
    assert!(header(&text).starts_with("void "), "{text}");
}

/// `pxor xmm0, xmm0; ret`: a written float lane no reading call decides is never void.
const FLOAT_WRITTEN: [u8; 0x25] = plt_then(&[
    0x66, 0x0f, 0xef, 0xc0, // 1020 pxor xmm0, xmm0
    0xc3, // 1024 ret
]);

#[test]
fn a_written_float_lane_is_never_void() {
    let text = rendered(Literal::plt_wrapped("free", &FLOAT_WRITTEN), PLT_CALLER);
    assert!(!header(&text).starts_with("void "), "{text}");
    assert!(text.contains("the result is unproven (Written)"), "{text}");
}

/// `*p = 0; ret`: RAX defines nothing, but XMM0, an input, still holds its entry byte (D208).
const LEAF: [u8; 0x27] = plt_then(&[
    0xc7, 0x07, 0x00, 0x00, 0x00, 0x00, // 1020 mov dword [rdi], 0
    0xc3, // 1026 ret
]);

#[test]
fn an_entry_float_lane_beside_an_undefined_integer_one_is_unproven() {
    let text = rendered(Literal::plt_wrapped("free", &LEAF), PLT_CALLER);
    assert!(!header(&text).starts_with("void "), "{text}");
    assert!(
        text.contains("the result is unproven (EntryInput)"),
        "{text}"
    );
}

fn aarch64(code: &'static [u8], functions: &[(&str, u64, u64)], at: u64) -> String {
    rendered(Literal::of_code(code, functions).in_aarch64(), at)
}

/// AArch64 `cbz w0, 1f; mov w0, #7; 1: ret`: one path hands back `arg0` in x0, an input.
const A64_HANDS_BACK: &[u8] = &[
    0x40, 0x00, 0x00, 0x34, // 1000 cbz w0, 0x1008
    0xe0, 0x00, 0x80, 0x52, // 1004 mov w0, #7
    0xc0, 0x03, 0x5f, 0xd6, // 1008 ret
];

#[test]
fn an_argument_handed_back_is_carried_not_trapped() {
    let text = aarch64(A64_HANDS_BACK, &[("f", common::BASE, 0x0c)], common::BASE);
    assert!(text.contains("r2sleigh_carrier_u"), "{text}");
    assert!(!text.contains("return r2sleigh_residual"), "{text}");
    assert!(
        text.contains("the result is unproven (EntryInput)"),
        "{text}"
    );
}

/// AArch64 `avg`'s shape: `cbz x0, 1f; ldr d0, [x0]; add x0, x0, #8; 1: ret`, a double in d0 beside
/// a pointer in x0; `caller` is `bl avg; fcvtzs w0, d0; ret`.
const A64_DOUBLE_BESIDE_POINTER: &[u8] = &[
    0x60, 0x00, 0x00, 0xb4, // 1000 cbz x0, 0x100c
    0x00, 0x00, 0x40, 0xfd, // 1004 ldr d0, [x0]
    0x00, 0x20, 0x00, 0x91, // 1008 add x0, x0, #8
    0xc0, 0x03, 0x5f, 0xd6, // 100c ret
    0xfd, 0x7b, 0xbf, 0xa9, // 1010 stp x29, x30, [sp, #-16]!
    0xfb, 0xff, 0xff, 0x97, // 1014 bl 0x1000
    0x00, 0x00, 0x78, 0x1e, // 1018 fcvtzs w0, d0
    0xfd, 0x7b, 0xc1, 0xa8, // 101c ldp x29, x30, [sp], #16
    0xc0, 0x03, 0x5f, 0xd6, // 1020 ret
];

/// Two carriers leave each call no contract cold (D62); under `aa` the caller's read of d0 decides
/// `avg`'s result per callee (D166), and the call assigns it.
#[test]
fn a_callee_s_float_lane_is_the_value_the_caller_reads() {
    let functions = [
        ("avg", common::BASE, 0x10),
        ("caller", common::BASE + 0x10, 0x14),
    ];
    let literal = Literal::of_code(A64_DOUBLE_BESIDE_POINTER, &functions).in_aarch64();
    let mut open = OpenProgram::of(literal);
    open.analyse_program().expect("it surveys");
    let rendering = open.rendered(common::BASE + 0x10).expect("it renders");
    let text = rendering.response.output.into_text();
    assert!(text.contains("double avg("), "{text}");
    assert!(!text.contains("never assigned"), "{text}");
    assert!(!text.contains("r2sleigh_residual_u128"), "{text}");
    let cold = aarch64(A64_DOUBLE_BESIDE_POINTER, &functions, common::BASE + 0x10);
    assert!(!cold.contains("double avg("), "{cold}");
}
