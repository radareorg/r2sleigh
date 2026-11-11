//! Per-lane fates at a call (doc/adr-call-boundary.md, "S16 as built"; D212, W46): what passes is the
//! caller's own, and a lane the callee's unproven result may be in is never void.

use crate::common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;

/// `pass` writes nothing; `some_paths` writes EAX on one path; `both` writes EAX and XMM0. The rest
/// call or tail to them, or through RSI; `fwd_*` restore RAX around the call (`push rax`, `pop rax`).
const LANES: &[u8] = &[
    0xc3, // 1000 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xb8,
    0x07, 0x00, 0x00, 0x00, // 1010 mov eax, 0x7
    0xeb, 0xe9, // 1015 jmp 0x1000
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xb8, 0x07, 0x00, 0x00,
    0x00, // 1020 mov eax, 0x7
    0xe8, 0xd6, 0xff, 0xff, 0xff, // 1025 call 0x1000
    0xc3, // 102a ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xeb, 0xce, // 1030 jmp 0x1000
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xf2, 0x0f,
    0x58, 0xc1, // 1040 addsd xmm0, xmm1
    0xeb, 0xba, // 1044 jmp 0x1000
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x85,
    0xff, // 1050 test edi, edi
    0x74, 0x05, // 1052 je 0x1059
    0xb8, 0x01, 0x00, 0x00, 0x00, // 1054 mov eax, 0x1
    0xc3, // 1059 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xb8, 0x07, 0x00, 0x00, 0x00, // 1060 mov eax, 0x7
    0xe8, 0xe6, 0xff, 0xff, 0xff, // 1065 call 0x1050
    0xc3, // 106a ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xb8, 0x07, 0x00, 0x00, 0x00, // 1070 mov eax, 0x7
    0xff, 0xd6, // 1075 call rsi
    0xc3, // 1077 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x50, // 1080 push rax
    0xff, 0xd6, // 1081 call rsi
    0x58, // 1083 pop rax
    0xc3, // 1084 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xe8, 0xeb, 0xff, 0xff,
    0xff, // 1090 call 0x1080
    0xf2, 0x0f, 0x11, 0x07, // 1095 movsd qword ptr [rdi], xmm0
    0xc3, // 1099 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xb8, 0x08, 0x00, 0x00, 0x00, // 10a0 mov eax, 0x8
    0xf2, 0x0f, 0x58, 0xc1, // 10a5 addsd xmm0, xmm1
    0xc3, // 10a9 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xe8, 0xeb, 0xff, 0xff, 0xff, // 10b0 call 0x10a0
    0xc3, // 10b5 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x50, // 10c0 push rax
    0xe8, 0xda, 0xff, 0xff, 0xff, // 10c1 call 0x10a0
    0x58, // 10c6 pop rax
    0xc3, // 10c7 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x31, 0xc0, // 10d0 xor eax, eax
    0x83, 0xff, 0x05, // 10d2 cmp edi, 0x5
    0x0f, 0x9c, 0xc0, // 10d5 setl al
    0xc3, // 10d8 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xbf, 0x03, 0x00, 0x00,
    0x00, // 10e0 mov edi, 0x3
    0xe8, 0xe6, 0xff, 0xff, 0xff, // 10e5 call 0x10d0
    0xc3, // 10ea ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

const FUNCTIONS: &[(&str, u64, u64)] = &[
    ("pass", BASE, 0x01),
    ("tail_kept", BASE + 0x10, 0x07),
    ("call_kept", BASE + 0x20, 0x0b),
    ("tail_entry", BASE + 0x30, 0x02),
    ("tail_float", BASE + 0x40, 0x06),
    ("some_paths", BASE + 0x50, 0x0a),
    ("call_some", BASE + 0x60, 0x0b),
    ("indirect", BASE + 0x70, 0x08),
    ("fwd_float", BASE + 0x80, 0x05),
    ("reads_fwd", BASE + 0x90, 0x0a),
    ("both", BASE + 0xa0, 0x0a),
    ("calls_both", BASE + 0xb0, 0x06),
    ("fwd_both", BASE + 0xc0, 0x08),
];

fn cold(at: u64) -> String {
    let rendered = OpenProgram::of(Literal::of_code(LANES, FUNCTIONS)).rendered(at);
    rendered.expect("it renders").response.output.into_text()
}

fn analysed(at: u64) -> String {
    let mut open = OpenProgram::of(Literal::of_code(LANES, FUNCTIONS));
    open.analyse_program().expect("it surveys");
    let rendered = open.rendered(at).expect("it renders");
    rendered.response.output.into_text()
}

/// `mov eax, 7; call pass; ret`: `pass` leaves RAX as found, so the 7 is what `call_kept` returns.
#[test]
fn a_call_that_passes_the_lane_keeps_the_callers_bytes() {
    let text = cold(BASE + 0x20);
    assert!(text.contains("return r2sleigh_carrier_u64(7);"), "{text}");
    assert!(text.contains("r2sleigh_result_u64 pass(void);"), "{text}");
}

/// A callee that writes EAX on one path only defines it at the call: the 7 is not returned.
#[test]
fn a_callee_that_leaves_the_lane_on_some_paths_only_defines_it() {
    let text = cold(BASE + 0x60);
    assert!(!text.contains("carrier_u64(7)"), "{text}");
    assert!(!text.starts_with("void "), "{text}");
}

/// An indirect target passes nothing: the 7 before `call rsi` is not the result.
#[test]
fn an_indirect_target_never_passes() {
    let text = cold(BASE + 0x70);
    assert!(!text.contains("carrier_u64(7)"), "{text}");
    assert!(!text.starts_with("void "), "{text}");
}

/// `jmp pass` hands back the caller's own lanes: XMM0's entry byte, EntryInput, never void.
#[test]
fn an_entry_lane_across_a_passing_tail_is_entry_input() {
    let text = cold(BASE + 0x30);
    assert!(text.contains("EntryInput"), "{text}");
    assert!(!text.starts_with("void "), "{text}");
}

/// `addsd xmm0, xmm1; jmp pass`: the written float reaches the return through the tail.
#[test]
fn a_float_written_before_a_passing_tail_is_never_void() {
    for text in [cold(BASE + 0x40), analysed(BASE + 0x40)] {
        assert!(!text.starts_with("void "), "{text}");
    }
}

/// `push rax; call rsi; pop rax; ret`, whose caller reads XMM0: the indirect callee's XMM0 is handed
/// back (ldb's `p_ldb_forward_b`), so the function is no void one, cold or under `aa`.
#[test]
fn a_float_an_unstated_call_leaves_is_never_void() {
    for text in [cold(BASE + 0x80), analysed(BASE + 0x80)] {
        assert!(!text.starts_with("void "), "{text}");
    }
}

/// `both` writes RAX and XMM0: a call to it states RAX, as its header does (W46), and XMM0 stays a
/// lane its result may be in, so `fwd_both` (RAX restored) is no void one.
#[test]
fn a_callee_with_two_written_lanes_mints_a_call_and_its_float_forwarder_is_not_void() {
    let header = cold(BASE + 0xa0);
    let header = header
        .lines()
        .find(|line| line.contains("both("))
        .expect("a header");
    let caller = cold(BASE + 0xb0);
    let declared = format!("    {header};");
    assert!(caller.lines().any(|line| line == declared), "{caller}");
    for text in [cold(BASE + 0xc0), analysed(BASE + 0xc0)] {
        assert!(!text.starts_with("void "), "{text}");
    }
}

/// AArch64 `fwd`: `mov x9, x30; bl pass; mov x30, x9; ret`; `pass` is `ret`, so x0 is the caller's own
/// past the call: an input handed back, EntryInput in the open world, never void.
const AARCH64: &[u8] = &[
    0xc0, 0x03, 0x5f, 0xd6, // 1000 ret
    0x1f, 0x20, 0x03, 0xd5, // 1004 nop
    0x1f, 0x20, 0x03, 0xd5, // 1008 nop
    0x1f, 0x20, 0x03, 0xd5, // 100c nop
    0xe9, 0x03, 0x1e, 0xaa, // 1010 mov x9, x30
    0xfb, 0xff, 0xff, 0x97, // 1014 bl 0x1000
    0xfe, 0x03, 0x09, 0xaa, // 1018 mov x30, x9
    0xc0, 0x03, 0x5f, 0xd6, // 101c ret
];

#[test]
fn an_aarch64_argument_passed_through_a_call_is_never_void() {
    let program = Literal::of_code(AARCH64, &[("pass", BASE, 0x04), ("fwd", BASE + 0x10, 0x10)]);
    let text = OpenProgram::of(program.in_aarch64())
        .rendered(BASE + 0x10)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(!text.starts_with("void fwd("), "{text}");
    assert!(text.contains("EntryInput"), "{text}");
}
