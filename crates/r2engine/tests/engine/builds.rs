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

/// `mov eax, 7; ret`, then `call 0x1000; ret`, then `call 0x1010; mov [rsi], eax; ret`: the leaf
/// keeps every register but its result, so its statement builds its caller again.
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
    assert!(!text.contains("r2sleigh_residual"), "{text}");
    let stats = open.analysis_stats();
    assert_eq!(stats.callee_reads.computed, 0, "{stats:?}");
    assert_eq!(stats.defects, 0, "{stats:?}");
}
