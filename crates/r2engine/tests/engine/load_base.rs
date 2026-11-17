//! A call or tail a branch decided over constants cuts off writes nothing, only in an image linked
//! at its addresses (D447): gABI chapter 5, "Base Address".

use crate::common::{BASE, Literal};
use r2abi::statement::LoadBase;
use r2engine::program::OpenProgram;

/// `main` stores 5 to `[rsp+8]`, calls `f` and returns the slot; `f` is `mov eax, K; <body>;
/// cmp rax, K; je out; jmp rax; out: ret`, with `body` before the compare.
fn program(body: &[u8]) -> (Vec<u8>, [(&'static str, u64, u64); 2]) {
    const MAIN: &[u8] = &[
        0x48, 0x83, 0xec, 0x18, // 1000 sub rsp, 0x18
        0x48, 0xc7, 0x44, 0x24, 0x08, 0x05, 0x00, 0x00, 0x00, // 1004 mov qword [rsp+8], 5
        0xe8, 0x0e, 0x00, 0x00, 0x00, // 100d call 0x1020
        0x48, 0x8b, 0x44, 0x24, 0x08, // 1012 mov rax, [rsp+8]
        0x48, 0x83, 0xc4, 0x18, // 1017 add rsp, 0x18
        0xc3, // 101b ret
        0xcc, 0xcc, 0xcc, 0xcc, // padding to 0x1020
    ];
    // K lies outside every mapped byte, so no walk resolves the jump to code.
    let tail = [
        &[0x48, 0x3d, 0x78, 0x56, 0x34, 0x12][..], // cmp rax, 0x12345678
        &[0x74, 0x02],                             // je out
        &[0xff, 0xe0],                             // jmp rax
        &[0xc3],                                   // out: ret
    ]
    .concat();
    let f = [&[0xb8, 0x78, 0x56, 0x34, 0x12][..], body, &tail].concat(); // mov eax, 0x12345678
    let functions = [("main", BASE, 0x1c), ("f", BASE + 0x20, f.len() as u64)];
    ([MAIN, &f].concat(), functions)
}

/// Whether `main` returns the 5 it stored: `f` writes none of its frame.
fn keeps_the_slot(body: &[u8], load: LoadBase) -> bool {
    let (code, functions) = program(body);
    let literal = Literal::of_code(Box::leak(code.into()), &functions).loaded(load);
    let rendered = OpenProgram::of(literal).rendered(BASE).expect("it renders");
    let text = rendered.response.output.into_text();
    (text.lines())
        .filter(|line| line.trim_start().starts_with("return"))
        .any(|line| line.contains('5'))
}

#[test]
fn a_tail_behind_a_compare_of_equal_constants_bounds_no_write() {
    assert!(keeps_the_slot(&[], LoadBase::Linked));
}

#[test]
fn a_slid_image_keeps_the_tail_a_write() {
    assert!(!keeps_the_slot(&[], LoadBase::Slid));
}

#[test]
fn an_unstated_load_base_keeps_the_tail_a_write() {
    assert!(!keeps_the_slot(&[], LoadBase::Unstated));
}

/// `mov rax, [rdi]` before the compare: a load is no constant.
#[test]
fn a_loaded_condition_keeps_the_tail_a_write() {
    assert!(!keeps_the_slot(&[0x48, 0x8b, 0x07], LoadBase::Linked));
}

/// `jmp rdi` behind `test edi, edi; je` before the compare: a transfer the walk cannot follow
/// stays, and an edge it may take into the cut block is in no graph.
#[test]
fn a_kept_unresolved_transfer_keeps_the_tail_a_write() {
    let body = [
        0x85, 0xff, // test edi, edi
        0x74, 0x02, // je over
        0xff, 0xe7, // jmp rdi
    ];
    assert!(!keeps_the_slot(&body, LoadBase::Linked));
}

/// `syscall` before the compare: an effect no model states may write what the compare reads.
#[test]
fn an_unmodelled_operation_keeps_the_tail_a_write() {
    assert!(!keeps_the_slot(&[0x0f, 0x05], LoadBase::Linked));
}
