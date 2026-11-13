//! AArch64's stack protector reads the C library's global `__stack_chk_guard`
//! (doc/adr-call-boundary.md, "S27 as built"): only a binding the container states places it.

use crate::common;

use common::{BASE, GLIBC, Literal, import_write};
use r2engine::program::{
    Applies, LoaderWrite, OpenProgram, Relocation, RelocationSymbol, Symbol, SymbolKind, WriteKind,
};

/// Where the fixtures keep the guard's word: a GOT slot, or the guard's own copy.
const WORD: u64 = BASE + 0x80;

/// clang -O2 `-fstack-protector-all -fPIC`: the guard read through its GOT slot before and after
/// the body, compared, and a mismatch calls `die`, which never returns. `f` returns 7.
const THROUGH_THE_GOT: &[u8] = &[
    0xff, 0x83, 0x00, 0xd1, // 1000 sub sp, sp, #0x20
    0xfd, 0x7b, 0x01, 0xa9, // 1004 stp x29, x30, [sp, #0x10]
    0xfd, 0x43, 0x00, 0x91, // 1008 add x29, sp, #0x10
    0x08, 0x00, 0x00, 0x90, // 100c adrp x8, 0x1000
    0x08, 0x41, 0x40, 0xf9, // 1010 ldr x8, [x8, #0x80]: the slot
    0x08, 0x01, 0x40, 0xf9, // 1014 ldr x8, [x8]: the guard
    0xa8, 0x83, 0x1f, 0xf8, // 1018 stur x8, [x29, #-8]
    0xe0, 0x00, 0x80, 0x52, // 101c mov w0, #7
    0x08, 0x00, 0x00, 0x90, // 1020 adrp x8, 0x1000
    0x08, 0x41, 0x40, 0xf9, // 1024 ldr x8, [x8, #0x80]: the slot
    0xa9, 0x83, 0x5f, 0xf8, // 1028 ldur x9, [x29, #-8]
    0x08, 0x01, 0x40, 0xf9, // 102c ldr x8, [x8]: the guard
    0x1f, 0x01, 0x09, 0xeb, // 1030 cmp x8, x9
    0x81, 0x00, 0x00, 0x54, // 1034 b.ne 0x1044
    0xfd, 0x7b, 0x41, 0xa9, // 1038 ldp x29, x30, [sp, #0x10]
    0xff, 0x83, 0x00, 0x91, // 103c add sp, sp, #0x20
    0xc0, 0x03, 0x5f, 0xd6, // 1040 ret
    0x01, 0x00, 0x00, 0x94, // 1044 bl 0x1048
    0x00, 0x00, 0x00, 0x14, // 1048 die: b 0x1048
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 104c padding
    0, 0, 0, 0, 0, 0, 0, 0, // 1080 the word
];

/// [`THROUGH_THE_GOT`] built `-fno-pic`: `add x8, x8, #0x80` addresses the guard's copy itself.
const AT_ITS_COPY: &[u8] = &{
    let mut code = [0u8; 0x88];
    let mut at = 0;
    while at < code.len() {
        code[at] = THROUGH_THE_GOT[at];
        at += 1;
    }
    let add = [0x08, 0x01, 0x02, 0x91]; // add x8, x8, #0x80
    let mut byte = 0;
    while byte < 4 {
        code[0x10 + byte] = add[byte];
        code[0x24 + byte] = add[byte];
        byte += 1;
    }
    code
};

const F: u64 = BASE;

fn functions(code: &'static [u8]) -> Literal {
    Literal::of_code(code, &[("f", F, 0x48), ("die", BASE + 0x48, 4)])
        .in_aarch64()
        .running_on(GLIBC)
}

/// The GOT slot the loader binds to `__stack_chk_guard`, sealed read-only.
fn bound(code: &'static [u8]) -> Literal {
    functions(code)
        .data_mapped_after(WORD)
        .loader_written(import_write(WORD, 8, "__stack_chk_guard"))
}

/// An `R_AARCH64_COPY` of `__stack_chk_guard` into the writable word.
fn copied(code: &'static [u8]) -> Literal {
    copied_into(functions(code), WORD)
}

fn copied_into(program: Literal, word: u64) -> Literal {
    program
        .writable_data_after(word)
        .relocated(Relocation {
            vaddr: word,
            ntype: 1024,
            width: 8,
            symbol: Some(Box::new(RelocationSymbol {
                name: "__stack_chk_guard".into(),
                ..RelocationSymbol::default()
            })),
            applies: Applies::Copy,
            ..Relocation::default()
        })
        .loader_written(LoaderWrite {
            place: word,
            width: 8,
            kind: WriteKind::Copy,
            encoding: r2engine::program::Encoding::Word,
        })
}

fn rendered(program: Literal) -> String {
    OpenProgram::of(program)
        .rendered(F)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// The proof line, which names what was assumed and what was left.
fn proof(text: &str) -> &str {
    (text.lines())
        .find(|line| line.contains("r2dec proof:"))
        .unwrap_or_else(|| panic!("a proof line: {text}"))
}

fn assert_elided(text: &str) {
    let proof = proof(text);
    assert!(
        proof.contains("compiler-inserted (assuming ub-free)"),
        "{text}"
    );
    assert!(
        !proof.contains("residual") && !proof.contains("unaccounted"),
        "{text}"
    );
    assert!(!text.contains("die"), "{text}");
    assert!(!text.contains("0x1080"), "{text}");
}

fn assert_kept(text: &str) {
    assert!(!text.contains("compiler-inserted"), "{text}");
    assert!(text.contains("0x1080"), "{text}");
}

/// The slot the loader binds to the guard holds its address, so both reads through it are the
/// guard's, and the check passes under the UB-free premise.
#[test]
fn a_canary_read_through_the_slot_its_import_binds_is_elided() {
    assert_elided(&rendered(bound(THROUGH_THE_GOT)));
}

/// The executable's copy of the guard is the one every image reads, at the address its record states.
#[test]
fn a_canary_read_at_its_copy_is_elided() {
    assert_elided(&rendered(copied(AT_ITS_COPY)));
}

/// A symbol named `__stack_chk_guard` at the word binds nothing: the loader writes no address there.
#[test]
fn a_defined_symbol_named_like_the_guard_binds_nothing() {
    let program = functions(THROUGH_THE_GOT)
        .data_mapped_after(WORD)
        .declaring(Symbol {
            name: "__stack_chk_guard".into(),
            vaddr: WORD,
            size: 8,
            kind: SymbolKind::Data,
            defined: true,
            ..Symbol::default()
        });
    assert_kept(&rendered(program));
}

/// A slot the program may write holds whatever was last stored: no read through it is the guard's.
#[test]
fn a_writable_slot_binds_nothing() {
    let program = functions(THROUGH_THE_GOT)
        .writable_data_after(WORD)
        .loader_written(import_write(WORD, 8, "__stack_chk_guard"));
    assert_kept(&rendered(program));
}

/// No C library named, no row: the bound slot is an ordinary word.
#[test]
fn without_a_library_row_the_bound_slot_is_no_guard() {
    let program = Literal::of_code(THROUGH_THE_GOT, &[("f", F, 0x48), ("die", BASE + 0x48, 4)])
        .in_aarch64()
        .needing(&[])
        .data_mapped_after(WORD)
        .loader_written(import_write(WORD, 8, "__stack_chk_guard"));
    assert_kept(&rendered(program));
}

/// gcc -O2 `shape_struct_array` without its check: the loop reads the frame through `x2`, a merge
/// of `sp` and `x2 + 8` the object model places in no frame object.
const WALKED_FRAME: &[u8] = &[
    0xff, 0x43, 0x00, 0xd1, // 1000 sub sp, sp, #0x10
    0xe0, 0x03, 0x00, 0xb9, // 1004 str w0, [sp]
    0xe1, 0x0b, 0x00, 0xb9, // 1008 str w1, [sp, #8]
    0xe2, 0x03, 0x00, 0x91, // 100c mov x2, sp
    0x01, 0x00, 0x80, 0x52, // 1010 mov w1, #0
    0x00, 0x00, 0x80, 0xd2, // 1014 mov x0, #0
    0x44, 0x84, 0x40, 0xb8, // 1018 ldr w4, [x2], #8
    0x00, 0x00, 0x04, 0x8b, // 101c add x0, x0, x4
    0x21, 0x04, 0x00, 0x11, // 1020 add w1, w1, #1
    0x3f, 0x08, 0x00, 0x71, // 1024 cmp w1, #2
    0x81, 0xff, 0xff, 0x54, // 1028 b.ne 0x1018
    0xff, 0x43, 0x00, 0x91, // 102c add sp, sp, #0x10
    0xc0, 0x03, 0x5f, 0xd6, // 1030 ret
];

/// A read through a frame address the model places in no frame object may land on any of them, so
/// no store is dead (aarch64 gcc-O2 `shape_struct_array` read unwritten stack bytes).
#[test]
fn a_frame_read_through_an_unplaced_walk_keeps_the_stores_it_may_read() {
    let program = Literal::of_code(WALKED_FRAME, &[("f", F, 0x34)])
        .in_aarch64()
        .running_on(GLIBC);
    let text = rendered(program);
    assert!(!text.contains("dead-frame-slot-store"), "{text}");
    assert!(
        text.contains("frame + 0U") || text.contains("(frame)"),
        "{text}"
    );
    assert_eq!(text.matches("r2sleigh_store_u32").count(), 2, "{text}");
}

/// [`WALKED_FRAME`] walking down from `sp + 8`: `ldr w4, [x2], #-8` reads the slot below.
const WALKED_DOWN: &[u8] = &{
    let mut code = [0u8; 0x34];
    let mut at = 0;
    while at < code.len() {
        code[at] = WALKED_FRAME[at];
        at += 1;
    }
    let (add, load) = ([0xe2, 0x23, 0x00, 0x91], [0x44, 0x84, 0x5f, 0xb8]);
    let mut byte = 0;
    while byte < 4 {
        code[0x0c + byte] = add[byte]; // add x2, sp, #8
        code[0x18 + byte] = load[byte]; // ldr w4, [x2], #-8
        byte += 1;
    }
    code
};

/// Only the object at `sp + 8` flows into the walk, and it steps down: the extent rule escapes
/// the run between compiler slots both ways (`close_upward`), so the store at `sp` stays.
#[test]
fn a_frame_walk_stepping_down_keeps_the_store_below_it() {
    let program = Literal::of_code(WALKED_DOWN, &[("f", F, 0x34)])
        .in_aarch64()
        .running_on(GLIBC);
    let text = rendered(program);
    assert_eq!(text.matches("r2sleigh_store_u32").count(), 2, "{text}");
}

/// aarch64 gcc -O2 `shape_pointer_to_pointer` (equivalence corpus), its callees `get` and `put`
/// first and `__stack_chk_fail` as `die`: four values at `sp + 8`, their addresses at `sp + 0x28`.
const POINTER_TABLE: &[u8] = &{
    let head: [u8; 0x114] = [
        0x00, 0x58, 0x61, 0xf8, // 1000 ldr x0, [x0, w1, uxtw #3]
        0x00, 0x00, 0x40, 0xf9, // 1004 ldr x0, [x0]
        0xc0, 0x03, 0x5f, 0xd6, // 1008 ret
        0x1f, 0x20, 0x03, 0xd5, // 100c nop
        0x00, 0x58, 0x61, 0xf8, // 1010 ldr x0, [x0, w1, uxtw #3]
        0x02, 0x00, 0x00, 0xf9, // 1014 str x2, [x0]
        0xc0, 0x03, 0x5f, 0xd6, // 1018 ret
        0x1f, 0x20, 0x03, 0xd5, // 101c nop
        0xff, 0x83, 0x01, 0xd1, // 1020 sub sp, sp, #0x60
        0xe2, 0x03, 0x01, 0xaa, // 1024 mov x2, x1
        0x64, 0x48, 0x88, 0xd2, // 1028 mov x4, #0x4243
        0x01, 0x00, 0x00, 0x90, // 102c adrp x1, 0x1000
        0x21, 0x60, 0x04, 0x91, // 1030 add x1, x1, #0x118: the guard's copy
        0x0a, 0x00, 0x02, 0xca, // 1034 eor x10, x0, x2
        0xfd, 0x7b, 0x05, 0xa9, // 1038 stp x29, x30, [sp, #80]
        0xfd, 0x43, 0x01, 0x91, // 103c add x29, sp, #0x50
        0x09, 0x00, 0x02, 0x8b, // 1040 add x9, x0, x2
        0xe7, 0x43, 0x00, 0x91, // 1044 add x7, sp, #0x10
        0x23, 0x00, 0x40, 0xf9, // 1048 ldr x3, [x1]
        0xe3, 0x27, 0x00, 0xf9, // 104c str x3, [sp, #72]
        0x03, 0x00, 0x80, 0xd2, // 1050 mov x3, #0x0
        0xe6, 0x63, 0x00, 0x91, // 1054 add x6, sp, #0x18
        0xe5, 0x83, 0x00, 0x91, // 1058 add x5, sp, #0x20
        0xe8, 0x23, 0x00, 0x91, // 105c add x8, sp, #0x8
        0x01, 0x00, 0x80, 0x52, // 1060 mov w1, #0x0
        0xe4, 0x01, 0xa0, 0xf2, // 1064 movk x4, #0xf, lsl #16
        0xe0, 0x8b, 0x00, 0xa9, // 1068 stp x0, x2, [sp, #8]
        0xea, 0xa7, 0x01, 0xa9, // 106c stp x10, x9, [sp, #24]
        0xe8, 0x9f, 0x02, 0xa9, // 1070 stp x8, x7, [sp, #40]
        0xe6, 0x97, 0x03, 0xa9, // 1074 stp x6, x5, [sp, #56]
        0x63, 0x7c, 0x04, 0x9b, // 1078 mul x3, x3, x4
        0xe0, 0xa3, 0x00, 0x91, // 107c add x0, sp, #0x28
        0xe0, 0xff, 0xff, 0x97, // 1080 bl 0x1000
        0x21, 0x04, 0x00, 0x11, // 1084 add w1, w1, #0x1
        0x63, 0x00, 0x00, 0x8b, // 1088 add x3, x3, x0
        0x3f, 0x10, 0x00, 0x71, // 108c cmp w1, #0x4
        0x41, 0xff, 0xff, 0x54, // 1090 b.ne 0x1078
        0xe2, 0x03, 0x03, 0xaa, // 1094 mov x2, x3
        0xe0, 0xa3, 0x00, 0x91, // 1098 add x0, sp, #0x28
        0x21, 0x00, 0x80, 0x52, // 109c mov w1, #0x1
        0xdc, 0xff, 0xff, 0x97, // 10a0 bl 0x1010
        0xe2, 0x07, 0x40, 0xf9, // 10a4 ldr x2, [sp, #8]
        0x61, 0x00, 0x80, 0x52, // 10a8 mov w1, #0x3
        0xe0, 0xa3, 0x00, 0x91, // 10ac add x0, sp, #0x28
        0x62, 0x00, 0x02, 0xca, // 10b0 eor x2, x3, x2
        0xd7, 0xff, 0xff, 0x97, // 10b4 bl 0x1010
        0x01, 0x00, 0x80, 0x52, // 10b8 mov w1, #0x0
        0x22, 0x04, 0x01, 0x0b, // 10bc add w2, w1, w1, lsl #1
        0xe0, 0xa3, 0x00, 0x91, // 10c0 add x0, sp, #0x28
        0xcf, 0xff, 0xff, 0x97, // 10c4 bl 0x1000
        0x21, 0x04, 0x00, 0x11, // 10c8 add w1, w1, #0x1
        0x00, 0x20, 0xc2, 0x9a, // 10cc lsl x0, x0, x2
        0x63, 0x00, 0x00, 0xca, // 10d0 eor x3, x3, x0
        0x3f, 0x10, 0x00, 0x71, // 10d4 cmp w1, #0x4
        0x21, 0xff, 0xff, 0x54, // 10d8 b.ne 0x10bc
        0x00, 0x00, 0x00, 0x90, // 10dc adrp x0, 0x1000
        0xe2, 0x27, 0x40, 0xf9, // 10e0 ldr x2, [sp, #72]
        0x01, 0x8c, 0x40, 0xf9, // 10e4 ldr x1, [x0, #0x118]
        0x42, 0x00, 0x01, 0xeb, // 10e8 subs x2, x2, x1
        0x01, 0x00, 0x80, 0xd2, // 10ec mov x1, #0x0
        0xa1, 0x00, 0x00, 0x54, // 10f0 b.ne 0x1104
        0xfd, 0x7b, 0x45, 0xa9, // 10f4 ldp x29, x30, [sp, #80]
        0xe0, 0x03, 0x03, 0xaa, // 10f8 mov x0, x3
        0xff, 0x83, 0x01, 0x91, // 10fc add sp, sp, #0x60
        0xc0, 0x03, 0x5f, 0xd6, // 1100 ret
        0x03, 0x00, 0x00, 0x94, // 1104 bl 0x1110: die
        0x1f, 0x20, 0x03, 0xd5, // 1108 nop
        0x1f, 0x20, 0x03, 0xd5, // 110c nop
        0x00, 0x00, 0x00, 0x14, // 1110 die: b 0x1110
    ];
    let mut code = [0u8; 0x120];
    let mut at = 0;
    while at < head.len() {
        code[at] = head[at];
        at += 1;
    }
    code
};

/// The canary at `sp + 0x48` lands inside the object at `sp + 0x10`, so it is no compiler slot
/// ending the escaped run: before, the run stopped there and three table stores were not spelled.
#[test]
fn a_canary_inside_a_frame_object_does_not_end_its_escape() {
    let functions = [
        ("get", BASE, 0x10),
        ("put", BASE + 0x10, 0x10),
        ("f", BASE + 0x20, 0xf0),
        ("die", BASE + 0x110, 4),
    ];
    let program = Literal::of_code(POINTER_TABLE, &functions)
        .in_aarch64()
        .running_on(GLIBC);
    let text = OpenProgram::of(copied_into(program, BASE + 0x118))
        .rendered(BASE + 0x20)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(text.contains("compiler-inserted"), "{text}");
    assert!(!text.contains("NotSpelled"), "{text}");
}
