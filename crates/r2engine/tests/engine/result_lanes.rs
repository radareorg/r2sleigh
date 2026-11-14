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
    assert!(text.contains("return r2sleigh_carrier_u32(7);"), "{text}");
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

/// `two` writes XMM0 and XMM1 from its arguments and `reads_two` adds both after the call; `one`
/// writes XMM0 alone and `reads_one` doubles it.
const GROUPS: &[u8] = &[
    0x66, 0x0f, 0xef, 0xc0, // 1000 pxor xmm0, xmm0
    0xf2, 0x48, 0x0f, 0x2a, 0xc7, // 1004 cvtsi2sd xmm0, rdi
    0x66, 0x0f, 0xef, 0xc9, // 1009 pxor xmm1, xmm1
    0xf2, 0x48, 0x0f, 0x2a, 0xce, // 100d cvtsi2sd xmm1, rsi
    0xc3, // 1012 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1013
    0x48, 0x83, 0xec, 0x08, // 1020 sub rsp, 8
    0xe8, 0xd7, 0xff, 0xff, 0xff, // 1024 call 0x1000
    0xf2, 0x0f, 0x58, 0xc1, // 1029 addsd xmm0, xmm1
    0x48, 0x83, 0xc4, 0x08, // 102d add rsp, 8
    0xc3, // 1031 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1032
    0x66, 0x0f, 0xef, 0xc0, // 1040 pxor xmm0, xmm0
    0xf2, 0x48, 0x0f, 0x2a, 0xc7, // 1044 cvtsi2sd xmm0, rdi
    0xc3, // 1049 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 104a
    0x48, 0x83, 0xec, 0x08, // 1050 sub rsp, 8
    0xe8, 0xe7, 0xff, 0xff, 0xff, // 1054 call 0x1040
    0xf2, 0x0f, 0x58, 0xc0, // 1059 addsd xmm0, xmm0
    0x48, 0x83, 0xc4, 0x08, // 105d add rsp, 8
    0xc3, // 1061 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

const GROUP_FUNCTIONS: &[(&str, u64, u64)] = &[
    ("two", BASE, 0x13),
    ("reads_two", BASE + 0x20, 0x12),
    ("one", BASE + 0x40, 0x0a),
    ("reads_one", BASE + 0x50, 0x12),
];

/// A float result whose following lane the body writes and a call reads is one group across both
/// lanes: no read of XMM0 alone decides `double`, and each lane stays a residual (S24, Decided 1).
#[test]
fn a_float_result_beside_a_written_and_read_second_lane_is_no_double() {
    let analysed = |at: u64| {
        let mut open = OpenProgram::of(Literal::of_code(GROUPS, GROUP_FUNCTIONS));
        open.analyse_program().expect("it surveys");
        let rendered = open.rendered(at).expect("it renders");
        rendered.response.output.into_text()
    };
    let one = analysed(BASE + 0x40);
    assert!(one.starts_with("double one("), "{one}");
    let two = analysed(BASE);
    assert!(!two.starts_with("double "), "{two}");
    assert!(!two.starts_with("void "), "{two}");
    assert!(two.contains("the result is unproven (Written)"), "{two}");
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

/// `narrow` writes EAX on one return path and leaves RAX unwritten on the other: no fill above.
/// `stores` writes XMM0 and EAX, so its result is unproven; `stores_whole` stores RAX whole.
const UNREAD_ABOVE: &[u8] = &[
    0x85, 0xff, // 1000 test edi, edi
    0x74, 0x04, // 1002 je 0x1008
    0x8d, 0x04, 0x7f, // 1004 lea eax, [rdi + rdi*2]
    0xc3, // 1007 ret
    0xc3, // 1008 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x66, 0x0f, 0xef, 0xc0, // 1010 pxor xmm0, xmm0
    0xe8, 0xe7, 0xff, 0xff, 0xff, // 1014 call 0x1000
    0x89, 0x06, // 1019 mov dword ptr [rsi], eax
    0xb8, 0x01, 0x00, 0x00, 0x00, // 101b mov eax, 0x1
    0xc3, // 1020 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x66,
    0x0f, 0xef, 0xc0, // 1030 pxor xmm0, xmm0
    0xe8, 0xc7, 0xff, 0xff, 0xff, // 1034 call 0x1000
    0x48, 0x89, 0x06, // 1039 mov qword ptr [rsi], rax
    0xb8, 0x01, 0x00, 0x00, 0x00, // 103c mov eax, 0x1
    0xc3, // 1041 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

fn unread_above(at: u64) -> String {
    let functions = &[
        ("narrow", BASE, 0x09),
        ("stores", BASE + 0x10, 0x11),
        ("stores_whole", BASE + 0x30, 0x12),
    ];
    let rendered = OpenProgram::of(Literal::of_code(UNREAD_ABOVE, functions)).rendered(at);
    rendered.expect("it renders").response.output.into_text()
}

/// A return whose result is unproven is a residual and reads no register, so the bytes of RAX above
/// `narrow`'s 32-bit result, which no store reads, are no residual at the call (ROADMAP D340).
#[test]
fn bits_above_a_call_result_no_store_reads_are_no_residual_where_the_return_is_unproven() {
    let text = unread_above(BASE + 0x10);
    assert!(text.starts_with("r2sleigh_result_u64 "), "{text}");
    assert!(text.contains("return r2sleigh_residual_u64(1);"), "{text}");
    assert!(!text.contains("<< 32"), "{text}");
}

/// The same caller storing RAX whole reads the bytes `narrow` does not state: they stay a residual.
#[test]
fn bits_above_a_call_result_a_store_reads_stay_a_residual_where_the_return_is_unproven() {
    let text = unread_above(BASE + 0x30);
    assert!(text.starts_with("r2sleigh_result_u64 "), "{text}");
    assert!(text.contains("| r2sleigh_residual_u64(1) << 32"), "{text}");
}

/// `leaf` writes EAX alone; `f` writes XMM0; `caller` calls `f`, then `leaf`, then stores XMM0;
/// `top` calls `caller`.
const KEPT: &[u8] = &[
    0xb8, 0x01, 0x00, 0x00, 0x00, // 1000 mov eax, 1
    0xc3, // 1005 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x66, 0x0f, 0xef,
    0xc0, // 1010 pxor xmm0, xmm0
    0xf2, 0x0f, 0x58, 0xc1, // 1014 addsd xmm0, xmm1
    0xc3, // 1018 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xe8, 0xeb, 0xff, 0xff,
    0xff, // 1020 call 0x1010
    0xe8, 0xd6, 0xff, 0xff, 0xff, // 1025 call 0x1000
    0xf2, 0x0f, 0x11, 0x07, // 102a movsd qword ptr [rdi], xmm0
    0xc3, // 102e ret
    0xcc, 0xe8, 0xeb, 0xff, 0xff, 0xff, // 1030 call 0x1020
    0xc3, // 1035 ret
    0xcc, 0xcc,
];

/// `call f; call leaf; movsd [rdi], xmm0`: `leaf` keeps XMM0 on every path to its return, so the
/// store reads what `f` left, and the closed world decides `f`'s result is the double it wrote.
#[test]
fn a_read_past_a_callee_that_keeps_the_lane_is_the_earlier_calls_read() {
    let functions = [
        ("leaf", BASE, 0x06),
        ("f", BASE + 0x10, 0x09),
        ("caller", BASE + 0x20, 0x0f),
    ];
    let mut open = OpenProgram::of(Literal::of_code(KEPT, &functions));
    open.analyse_program().expect("it surveys");
    let rendered = open.rendered(BASE + 0x10).expect("it renders");
    let text = rendered.response.output.into_text();
    assert!(text.starts_with("double f("), "{text}");
    assert_eq!(open.analysis_stats().defects, 0);
}

/// `caller`'s register effect is deposited by its own site fates where `f` is decided first, and
/// asked directly where `top` is: each order renders every function alike (ADR, "S31b as built").
#[test]
fn a_deposited_register_effect_renders_as_the_one_asked_directly() {
    let functions = [
        ("leaf", BASE, 0x06),
        ("f", BASE + 0x10, 0x09),
        ("caller", BASE + 0x20, 0x0f),
        ("top", BASE + 0x30, 0x06),
    ];
    let rendered = |order: [u64; 4]| {
        let mut open = OpenProgram::of(Literal::of_code(KEPT, &functions));
        open.analyse_program().expect("it surveys");
        let mut texts = order.map(|at| {
            let rendered = open.rendered(at).expect("it renders");
            (at, rendered.response.output.into_text())
        });
        texts.sort();
        assert_eq!(open.analysis_stats().defects, 0);
        texts
    };
    let deposited = rendered([BASE + 0x10, BASE + 0x20, BASE + 0x30, BASE]);
    let asked = rendered([BASE + 0x20, BASE + 0x10, BASE + 0x30, BASE]);
    assert_eq!(deposited, asked);
}

/// `stores` of [`UNREAD_ABOVE`], then `test eax, eax; jne 1f; jmp free; 1: mov eax, 1; ret`.
fn tail_to_free() -> &'static [u8] {
    let mut code = [0xcc_u8; 0xa0];
    code[..9].copy_from_slice(&UNREAD_ABOVE[..9]);
    code[0x10..0x1b].copy_from_slice(&UNREAD_ABOVE[0x10..0x1b]);
    code[0x1b..0x2a].copy_from_slice(&[
        0x85, 0xc0, 0x75, 0x05, 0xe9, 0x6c, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0xc3,
    ]);
    code[0x90..0x96].copy_from_slice(&common::JUMP_STUB);
    code[0x98..].fill(0);
    Box::leak(Box::new(code))
}

/// A tail transfer to a `void` import reads its arguments, and no caller reads an unproven
/// result, so the bytes above `narrow`'s 32-bit result are no residual at the call (D211).
#[test]
fn a_tail_to_a_void_callee_names_its_exit() {
    let functions = &[("narrow", BASE, 0x09), ("stores", BASE + 0x10, 0x1a)];
    let literal = Literal::of_code(tail_to_free(), functions).importing("free");
    let rendered = OpenProgram::of(literal).rendered(BASE + 0x10);
    let text = rendered.expect("it renders").response.output.into_text();
    assert!(!text.contains("<< 32"), "{text}");
    assert!(
        text.contains("rax_1 = (uint64_t)narrow((uint32_t)arg0);"),
        "{text}"
    );
}

/// [`tail_to_free`] tailing into `printf`: a variadic tail reads every register a call reads
/// unnamed and `printf`'s `int`, so `narrow`'s upper bytes stay unread and no residual (D373).
#[test]
fn a_tail_to_a_variadic_callee_names_its_exit() {
    let functions = &[("narrow", BASE, 0x09), ("stores", BASE + 0x10, 0x1a)];
    let literal = Literal::of_code(tail_to_free(), functions).importing("printf");
    let rendered = OpenProgram::of(literal).rendered(BASE + 0x10);
    let text = rendered.expect("it renders").response.output.into_text();
    assert!(text.contains("call to printf: variadic"), "{text}");
    assert!(!text.contains("<< 32"), "{text}");
    assert!(
        text.contains("rax_1 = (uint64_t)narrow((uint32_t)arg0);"),
        "{text}"
    );
}

/// `narrow` of [`UNREAD_ABOVE`]; `tails`: `pxor xmm0, xmm0; call narrow; <between>; jmp stub`,
/// the stub an import no row states.
fn tail_to_unstated(between: &[u8]) -> &'static [u8] {
    let mut code = [0xcc_u8; 0xa0];
    code[..9].copy_from_slice(&UNREAD_ABOVE[..9]);
    code[0x10..0x19].copy_from_slice(&UNREAD_ABOVE[0x10..0x19]);
    let jump = 0x19 + between.len();
    code[0x19..jump].copy_from_slice(between);
    let rel = i32::try_from(0x90 - (jump + 5)).expect("a near jump");
    code[jump] = 0xe9;
    code[jump + 1..jump + 5].copy_from_slice(&rel.to_le_bytes());
    code[0x90..0x96].copy_from_slice(&common::JUMP_STUB);
    code[0x98..].fill(0);
    Box::leak(Box::new(code))
}

/// The bytes demand reads of the RAX `call narrow` leaves, in `tails` of [`tail_to_unstated`].
fn demanded_of_narrow(between: &[u8]) -> Option<u64> {
    demanded_tailing_into(between, "unstated")
}

/// [`demanded_of_narrow`], the stub `import`.
fn demanded_tailing_into(between: &[u8], import: &str) -> Option<u64> {
    let functions = &[("narrow", BASE, 0x09), ("tails", BASE + 0x10, 0x30)];
    let literal = Literal::of_code(tail_to_unstated(between), functions).importing(import);
    let mut open = OpenProgram::of(literal);
    let prepared = open.prepared(BASE + 0x10).expect("it prepares");
    let artifact = prepared.artifact().shared_artifact();
    let graph = artifact.graph();
    let rax = (graph.insts.iter())
        .find_map(|inst| match graph.op(inst.id) {
            Some(r2ssa::SSAOp::CallDefine { dst }) => graph
                .value(*dst)
                .and_then(|value| value.canonical_storage)
                .filter(|storage| storage.offset == 0 && storage.size == 8)
                .map(|_| *dst),
            _ => None,
        })
        .expect("the RAX the call defines");
    artifact
        .facts()
        .demanded
        .as_ref()
        .map(|demand| demand.bytes(rax))
}

/// A tail to an unstated callee reads the count register: of the RAX `narrow` leaves, nothing
/// but AL's byte reaches the exit, so demand reads that byte alone (D373).
#[test]
fn a_tail_to_an_unstated_callee_reads_its_count_register() {
    assert_eq!(demanded_of_narrow(&[]), Some(0x1));
}

/// Default-deny: an unstated tail reads every argument register whole, so `mov rdi, rax` hands
/// `narrow`'s undefined upper bytes on and demand reads all eight (D373).
#[test]
fn a_tail_to_an_unstated_callee_reads_its_argument_registers_whole() {
    assert_eq!(demanded_of_narrow(&[0x48, 0x89, 0xc7]), Some(0xff));
}

/// `test edi, edi; je tail; movabs rax, imm64; ret`: a direct return proves a 64-bit result.
const WIDE_BESIDE: &[u8] = &[
    0x85, 0xff, 0x74, 0x0b, 0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xc3,
];

/// A tail whose callee states no narrower result passes ours: beside a 64-bit return, all eight
/// bytes of the RAX `narrow` leaves reach the caller (D373).
#[test]
fn a_tail_stating_no_narrower_result_passes_a_wide_result_whole() {
    assert_eq!(demanded_tailing_into(WIDE_BESIDE, "unstated"), Some(0xff));
    assert_eq!(demanded_tailing_into(WIDE_BESIDE, "free"), Some(0xff));
}
