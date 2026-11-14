//! A callee's result is resolved from one build of it: the owners its build names are resolved
//! first, and their statements update that build (doc/adr-callee-builds.md).

use crate::common;

use common::{BASE, Literal, plt_then};
use r2engine::program::OpenProgram;

/// `frees` calls the stub for `free`, `forwards` calls `frees`, and the root calls `forwards`.
const FORWARDS: [u8; 0x4e] = plt_then(&[
    0x48, 0x83, 0xec, 0x08, // 1020 sub rsp, 8
    0xe8, 0xe7, 0xff, 0xff, 0xff, // 1024 call the stub
    0x48, 0x83, 0xc4, 0x08, // 1029 add rsp, 8
    0xc3, // 102d ret
    0xcc, 0xcc, // 102e padding
    0x48, 0x83, 0xec, 0x08, // 1030 sub rsp, 8
    0xe8, 0xe7, 0xff, 0xff, 0xff, // 1034 call 0x1020
    0x48, 0x83, 0xc4, 0x08, // 1039 add rsp, 8
    0xc3, // 103d ret
    0xcc, 0xcc, // 103e padding
    0x48, 0x83, 0xec, 0x08, // 1040 sub rsp, 8
    0xe8, 0xe7, 0xff, 0xff, 0xff, // 1044 call 0x1030
    0x48, 0x83, 0xc4, 0x08, // 1049 add rsp, 8
    0xc3, // 104d ret
]);

const FORWARDS_AT: u64 = BASE + 0x30;
const ROOT: u64 = BASE + 0x40;

fn rendered(open: &mut OpenProgram<Literal>, at: u64) -> String {
    let rendering = open.rendered(at).expect("it renders");
    rendering.response.output.into_text()
}

/// `forwards` is `void` only against `frees`, whose statement keeps the build that named it; a
/// debug build panics where that build differs from one made anew, leaving `forwards` unread.
#[test]
fn an_owners_statement_updates_the_build_that_named_it() {
    let mut open = OpenProgram::of(Literal::plt_wrapped("free", &FORWARDS));
    let text = rendered(&mut open, ROOT);
    assert!(
        text.contains(&format!("void fcn_{FORWARDS_AT:x}(")),
        "{text}"
    );
    let stats = open.analysis_stats();
    // No callee is read alone and then again against its owners.
    assert_eq!(stats.callee_reads.computed, 0, "{stats:?}");
    assert_eq!(stats.defects, 0, "{stats:?}");
}

/// The root renders as it does where `forwards` is asked for first, alone and then as a callee.
#[test]
fn a_callee_resolved_from_its_build_reads_as_one_rendered_first() {
    let program = || Literal::plt_wrapped("free", &FORWARDS);
    let mut first = OpenProgram::of(program());
    assert!(!rendered(&mut first, FORWARDS_AT).is_empty());
    let after = rendered(&mut first, ROOT);
    assert_eq!(after, rendered(&mut OpenProgram::of(program()), ROOT));
}

/// `mov eax, 7; ret`, then `call 0x1000; ret`, then `call 0x1010; mov [rsi], eax; ret`: the leaf's
/// statement builds its caller again.
const VALUE: &[u8] = &[
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1000 mov eax, 7
    0xc3, // 1005 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1006 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0xc3, // 1015 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1016 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1020 call 0x1010
    0x89, 0x06, // 1025 mov [rsi], eax
    0xc3, // 1027 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1028 padding
];

#[test]
fn an_owner_that_moves_the_build_has_it_built_again() {
    let functions = [
        ("leaf", BASE, 0x06),
        ("middle", BASE + 0x10, 0x06),
        ("root", BASE + 0x20, 0x08),
    ];
    let mut open = OpenProgram::of(Literal::of_code(VALUE, &functions));
    let text = rendered(&mut open, BASE + 0x20);
    // The leaf's `mov eax, 7` states zero above its 32-bit result (D322).
    assert!(text.contains("= (uint64_t)middle()"), "{text}");
    // `middle` keeps what `leaf` keeps across its call, so the store's rsi is the root's (D363).
    assert!(!text.contains("r2sleigh_residual"), "{text}");
    assert!(!text.contains("never assigned"), "{text}");
    let stats = open.analysis_stats();
    assert_eq!(stats.callee_reads.computed, 0, "{stats:?}");
    assert_eq!(stats.rebuilt, 1, "{stats:?}");
    assert_eq!(stats.defects, 0, "{stats:?}");
}

/// `mov eax, 7; ret`, then `call 0x1000; mov [rsi], eax; ret`.
const KEEPS_RSI: &[u8] = &[
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1000 mov eax, 7
    0xc3, // 1005 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1006 padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x89, 0x06, // 1015 mov [rsi], eax
    0xc3, // 1017 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1018 padding
];

/// The leaf's register effect keeps rsi, so the call keeps it: the caller stores through its own
/// rsi (D320: what a callee keeps is its `RegisterEffect.kept`, the one owner).
#[test]
fn a_callee_whose_register_effect_keeps_rsi_keeps_it_across_the_call() {
    let functions = [("leaf", BASE, 0x06), ("root", BASE + 0x10, 0x08)];
    let mut open = OpenProgram::of(Literal::of_code(KEEPS_RSI, &functions));
    let text = rendered(&mut open, BASE + 0x10);
    assert!(text.contains("leaf()"), "{text}");
    assert!(!text.contains("r2sleigh_residual"), "{text}");
}

/// `test edi, edi; je L; call rec; L: ret`, then `call rec; mov [rsi], eax; ret`.
const RECURSES: &[u8] = &[
    0x85, 0xff, // 1000 test edi, edi
    0x74, 0x05, // 1002 je 0x1009
    0xe8, 0xf7, 0xff, 0xff, 0xff, // 1004 call 0x1000
    0xc3, // 1009 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 100a padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x89, 0x06, // 1015 mov [rsi], eax
    0xc3, // 1017 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1018 padding
];

/// `rec` writes no rsi, but its returning path calls itself: a cycle keeps nothing, so the
/// caller's rsi past the call stays a residual (D363, default-deny).
#[test]
fn a_callee_that_calls_itself_on_a_returning_path_keeps_nothing() {
    let functions = [("rec", BASE, 0x0a), ("root", BASE + 0x10, 0x08)];
    let mut open = OpenProgram::of(Literal::of_code(RECURSES, &functions));
    let text = rendered(&mut open, BASE + 0x10);
    assert!(
        text.contains("never assigned, read as residuals (RSI"),
        "{text}"
    );
    assert_eq!(open.analysis_stats().defects, 0);
}

/// `clear(p, f)`: `mov dword [rdi], 0; xor edi, edi; call rsi; mov eax, 7; ret`; `middle`: `mov edi, 0x3000; call clear;
/// ret`; the root: `call middle; mov [rsi], eax; ret`.
const REACHES_UPWARD: &[u8] = &[
    0xc7, 0x07, 0x00, 0x00, 0x00, 0x00, // 1000 mov dword [rdi], 0
    0x31, 0xff, // 1006 xor edi, edi
    0xff, 0xd6, // 1008 call rsi
    0xb8, 0x07, 0x00, 0x00, 0x00, // 100a mov eax, 7
    0xc3, // 100f ret
    0xbf, 0x00, 0x30, 0x00, 0x00, // 1010 mov edi, 0x3000
    0xe8, 0xe6, 0xff, 0xff, 0xff, // 1015 call 0x1000
    0xc3, // 101a ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 101b padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1020 call 0x1010
    0x89, 0x06, // 1025 mov [rsi], eax
    0xc3, // 1027 ret
];

/// `clear` reaches its first argument upward, and `middle` hands it no frame address, so the
/// reach decides nothing in `middle`'s build: `clear`'s statement keeps it (D365).
#[test]
fn a_reach_promotion_never_asked_keeps_the_build() {
    let functions = [
        ("clear", BASE, 0x10),
        ("middle", BASE + 0x10, 0x0b),
        ("root", BASE + 0x20, 0x08),
    ];
    let mut open = OpenProgram::of(Literal::of_code(REACHES_UPWARD, &functions));
    let text = rendered(&mut open, BASE + 0x20);
    assert!(text.contains("= middle(arg0, arg1);"), "{text}");
    let stats = open.analysis_stats();
    // Comparing every reach the key holds built `middle` twice.
    assert_eq!(stats.rebuilt, 0, "{stats:?}");
    assert_eq!(stats.defects, 0, "{stats:?}");
}

/// `forwards`' build is kept against `frees`' statement, whose areas moved and decide nothing, so
/// its second recovery borrows the static phases its first collected: one prefix per build and
/// per seal, 9 on the parent (D289). The debug oracle's rebuild is unmetered.
#[test]
fn a_kept_build_collects_its_static_phases_once() {
    let mut open = OpenProgram::of(Literal::plt_wrapped("free", &FORWARDS));
    let _ = rendered(&mut open, ROOT);
    let stats = open.analysis_stats();
    assert_eq!(stats.rebuilt, 0, "{stats:?}");
    assert_eq!(stats.static_prefixes, 8, "{stats:?}");
    assert_eq!(stats.defects, 0, "{stats:?}");
}

/// `clear` as above; `middle`: `sub rsp, 0x18; lea rdi, [rsp + 8]; mov [0x3000], rdi; call clear;
/// add rsp, 0x18; ret`; the root: `call middle; mov [rsi], eax; ret`.
const HANDS_A_SLOT_UPWARD: &[u8] = &[
    0xc7, 0x07, 0x00, 0x00, 0x00, 0x00, // 1000 mov dword [rdi], 0
    0x31, 0xff, // 1006 xor edi, edi
    0xff, 0xd6, // 1008 call rsi
    0xb8, 0x07, 0x00, 0x00, 0x00, // 100a mov eax, 7
    0xc3, // 100f ret
    0x48, 0x83, 0xec, 0x18, // 1010 sub rsp, 0x18
    0x48, 0x8d, 0x7c, 0x24, 0x08, // 1014 lea rdi, [rsp + 8]
    0x48, 0x89, 0x3c, 0x25, 0x00, 0x30, 0x00, 0x00, // 1019 mov [0x3000], rdi
    0xe8, 0xda, 0xff, 0xff, 0xff, // 1021 call 0x1000
    0x48, 0x83, 0xc4, 0x18, // 1026 add rsp, 0x18
    0xc3, // 102a ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 102b padding
    0xe8, 0xdb, 0xff, 0xff, 0xff, // 1030 call 0x1010
    0x89, 0x06, // 1035 mov [rsi], eax
    0xc3, // 1037 ret
];

/// `middle` hands its slot's address to `clear`, which turns out to reach only upward, and also
/// stores it to memory: the slot escapes either way whatever `clear` states, so the frame walk's
/// decision stands and the build is kept with no propagation (D365 rule 2); the parent built it
/// twice, the asked reach flipped. A debug build compares it with a rebuild.
#[test]
fn a_reach_that_moves_no_decision_keeps_the_build() {
    let functions = [
        ("clear", BASE, 0x10),
        ("middle", BASE + 0x10, 0x1b),
        ("root", BASE + 0x30, 0x08),
    ];
    let mut open = OpenProgram::of(Literal::of_code(HANDS_A_SLOT_UPWARD, &functions));
    let text = rendered(&mut open, BASE + 0x30);
    assert!(text.contains("= middle(arg0, arg1);"), "{text}");
    let stats = open.analysis_stats();
    assert_eq!(stats.rebuilt, 0, "{stats:?}");
    // Built again, `middle` walks 13 more values (47); the restatement decides its 1 sink point.
    assert_eq!(stats.frame_walk_steps, 34, "{stats:?}");
    assert_eq!(stats.frame_decision_steps, 3, "{stats:?}");
    assert_eq!(stats.defects, 0, "{stats:?}");
}
