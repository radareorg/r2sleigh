//! A parameter handed whole to callees that load or store through it is a pointer to the one width
//! they access at, else unproven with the cause named (ROADMAP D610).

use crate::common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;

/// The function at `at` rendered after `aa`.
fn rendered(program: Literal, at: u64) -> String {
    let mut open = OpenProgram::of(program);
    open.analyse_program().expect("it surveys");
    let rendering = open.rendered(at).expect("it renders");
    rendering.response.output.into_text()
}

/// `g` reads a byte through `rdi`; `f` hands its `rdi` to `g` untouched; `k` calls `f`.
const ONE_WIDTH: &[u8] = &[
    0x0f, 0xb6, 0x07, // 1000 g: movzx eax, byte [rdi]
    0xc3, // 1003 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1004 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 f: call g
    0xc3, // 1015 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1016 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1020 k: call f
    0xc3, // 1025 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1026 padding
];

/// `g` reads a byte and `h` a dword through `rdi`; `f` hands its `rdi` to both; `k` calls `f`.
const TWO_WIDTHS: &[u8] = &[
    0x0f, 0xb6, 0x07, // 1000 g: movzx eax, byte [rdi]
    0xc3, // 1003 ret
    0xcc, 0xcc, 0xcc, 0xcc, // 1004 padding
    0x8b, 0x07, // 1008 h: mov eax, [rdi]
    0xc3, // 100a ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 100b padding
    0x53, // 1010 f: push rbx
    0x48, 0x89, 0xfb, // 1011 mov rbx, rdi
    0xe8, 0xe7, 0xff, 0xff, 0xff, // 1014 call g
    0x48, 0x89, 0xdf, // 1019 mov rdi, rbx
    0xe8, 0xe7, 0xff, 0xff, 0xff, // 101c call h
    0x5b, // 1021 pop rbx
    0xc3, // 1022 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1023 padding
    0xe8, 0xdb, 0xff, 0xff, 0xff, // 1030 k: call f
    0xc3, // 1035 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1036 padding
];

/// `m` reads a dword through `rdi`; `g` reads a byte through it and hands it on to `m`; `f` hands
/// its `rdi` to `g` alone.
const ONE_WIDTH_HANDED_ON: &[u8] = &[
    0x8b, 0x07, // 1000 m: mov eax, [rdi]
    0xc3, // 1002 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1003 padding
    0x0f, 0xb6, 0x07, // 1008 g: movzx eax, byte [rdi]
    0xe8, 0xf0, 0xff, 0xff, 0xff, // 100b call m
    0xc3, // 1010 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1011 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1018 f: call g
    0xc3, // 101d ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, // 101e padding
];

/// The one width its callee reads through it is the pointee; the body states no sign (D610).
#[test]
fn a_parameter_handed_whole_to_a_byte_reader_points_at_a_byte() {
    let functions = [("g", BASE, 4), ("f", BASE + 0x10, 6), ("k", BASE + 0x20, 6)];
    let text = rendered(Literal::of_code(ONE_WIDTH, &functions), BASE + 0x10);
    assert!(text.contains(" f(r2sleigh_word_u8* arg0)"), "{text}");
    assert!(!text.contains("is unproven (PointeeWidths)"), "{text}");
    // The caller declares it as its header does.
    let caller = rendered(Literal::of_code(ONE_WIDTH, &functions), BASE + 0x20);
    assert!(caller.contains(" f(r2sleigh_word_u8*)"), "{caller}");
}

/// Two widths state no pointee: the parameter is unproven, its cause on the proof line, and no
/// integer is claimed (D610; source-gold `combined` parameter 0).
#[test]
fn two_callees_reading_two_widths_leave_the_parameter_unproven() {
    let functions = [
        ("g", BASE, 4),
        ("h", BASE + 0x08, 3),
        ("f", BASE + 0x10, 0x13),
        ("k", BASE + 0x30, 6),
    ];
    let text = rendered(Literal::of_code(TWO_WIDTHS, &functions), BASE + 0x10);
    assert!(text.contains(" f(r2sleigh_unproven_u64 arg0)"), "{text}");
    assert!(
        text.contains("parameter 0 is unproven (PointeeWidths)"),
        "{text}"
    );
    let caller = rendered(Literal::of_code(TWO_WIDTHS, &functions), BASE + 0x30);
    assert!(caller.contains(" f(r2sleigh_unproven_u64)"), "{caller}");
}

/// Default deny: a callee that hands the parameter on states only its own accesses, so the byte
/// it reads is no pointee where a further callee may read another width.
#[test]
fn a_callee_handing_the_parameter_on_leaves_the_pointee_unproven() {
    let functions = [("m", BASE, 3), ("g", BASE + 0x08, 9), ("f", BASE + 0x18, 6)];
    let program = Literal::of_code(ONE_WIDTH_HANDED_ON, &functions);
    let text = rendered(program, BASE + 0x18);
    assert!(text.contains(" f(r2sleigh_unproven_u64 arg0)"), "{text}");
    assert!(
        text.contains("parameter 0 is unproven (PointeeWidths)"),
        "{text}"
    );
}
