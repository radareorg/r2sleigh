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
    functions(code)
        .writable_data_after(WORD)
        .relocated(Relocation {
            vaddr: WORD,
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
            place: WORD,
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
