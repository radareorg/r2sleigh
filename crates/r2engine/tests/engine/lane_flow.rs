//! One lift per body (D589): a body lifted for its register effect hands its own `SiteFates` the
//! lane flow, so the format a call folds is read once and the body is never lifted again.

use crate::common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;

/// `f` at `BASE + 8` is `ret`; `caller` at `BASE + 0x10` holds `caller_words`; `outer` at
/// `BASE + 0x40` calls it and returns its x0. Rendering `outer` lifts `caller` for its register
/// effect; rendering `f` then asks `caller`'s own fates.
fn program(caller_words: &[(u64, u32)], format: &[u8]) -> OpenProgram<Literal> {
    let mut code = vec![0u8; 0xb0];
    let outer = [
        (BASE + 0x40, 0xa9bf_7bfd), // stp x29, x30, [sp, #-16]!
        (BASE + 0x44, 0x97ff_fff3), // bl caller
        (BASE + 0x48, 0xa8c1_7bfd), // ldp x29, x30, [sp], #16
        (BASE + 0x4c, 0xd65f_03c0), // ret
    ];
    let words = [(BASE + 0x08, 0xd65f_03c0)]
        .iter()
        .chain(caller_words)
        .chain(&outer);
    for (at, word) in words {
        let at = (*at - BASE) as usize;
        code[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    code[0x90..0x94].copy_from_slice(&0x5800_0050u32.to_le_bytes()); // printf: ldr x16, #8
    code[0x94..0x98].copy_from_slice(&0xd61f_0200u32.to_le_bytes()); // br x16
    let code = Box::leak(code.into_boxed_slice());
    let functions = [
        ("f", BASE + 0x08, 0x04),
        ("caller", BASE + 0x10, 0x30),
        ("outer", BASE + 0x40, 0x14),
    ];
    let program = Literal::of_code(code, &functions)
        .in_aarch64()
        .with_data()
        .importing("printf");
    let mut open = OpenProgram::of(program);
    open.source_mut().write(common::TEXT, format);
    open
}

/// `caller` folds its format in the call's block: `adrp x19; add x19; bl f; mov x0, x19; bl printf`.
const FOLDED: [(u64, u32); 9] = [
    (BASE + 0x10, 0xa9bf_7bfd), // stp x29, x30, [sp, #-16]!
    (BASE + 0x14, 0x9000_0013), // adrp x19, 0x1000
    (BASE + 0x18, 0x9102_8273), // add x19, x19, #0xa0
    (BASE + 0x1c, 0x97ff_fffb), // bl f
    (BASE + 0x20, 0xaa13_03e0), // mov x0, x19
    (BASE + 0x24, 0x5280_00e1), // mov w1, #7
    (BASE + 0x28, 0x9400_001a), // bl printf
    (BASE + 0x2c, 0xa8c1_7bfd), // ldp x29, x30, [sp], #16
    (BASE + 0x30, 0xd65f_03c0), // ret
];

/// `caller` spills the format and reloads it in the next block, which only the seal folds (Gb).
const SEALED: [(u64, u32); 12] = [
    (BASE + 0x10, 0xa9be_7bfd), // stp x29, x30, [sp, #-32]!
    (BASE + 0x14, 0x9000_0008), // adrp x8, 0x1000
    (BASE + 0x18, 0x9102_8108), // add x8, x8, #0xa0
    (BASE + 0x1c, 0xf900_0be8), // str x8, [sp, #16]
    (BASE + 0x20, 0xd503_201f), // nop
    (BASE + 0x24, 0x97ff_fff9), // bl f
    (BASE + 0x28, 0x1400_0001), // b 0x102c
    (BASE + 0x2c, 0xf940_0be0), // ldr x0, [sp, #16]
    (BASE + 0x30, 0x5280_00e1), // mov w1, #7
    (BASE + 0x34, 0x9400_0017), // bl printf
    (BASE + 0x38, 0xa8c2_7bfd), // ldp x29, x30, [sp], #32
    (BASE + 0x3c, 0xd65f_03c0), // ret
];

/// `f` under `aa` after `outer`, and the bodies `SiteFates` lifted again.
fn rendered_f(caller: &[(u64, u32)], format: &[u8]) -> (String, u64) {
    let mut open = program(caller, format);
    open.analyse_program().expect("it surveys");
    open.rendered(BASE + 0x40).expect("outer renders");
    let rendered = open.rendered(BASE + 0x08).expect("it renders");
    let stats = open.analysis_stats();
    assert_eq!(stats.defects, 0, "{stats:?}");
    (
        rendered.response.output.into_text(),
        stats.site_fates_relifted,
    )
}

/// D218 through the projection: the format folds in the block, so q0 to q3 die at `printf` and
/// `f` is void; `caller`'s `SiteFates` reads the flow its effect's lift left, lifting it no more.
#[test]
fn a_format_folded_in_its_block_is_read_from_the_lift_that_gave_the_effect() {
    let (text, relifted) = rendered_f(&FOLDED, b"%d\n\0");
    assert!(text.starts_with("void f("), "{text}");
    assert_eq!(relifted, 0);
    // A float conversion keeps q0 taken, through the projection as through the lift.
    let (text, relifted) = rendered_f(&FOLDED, b"%f\n\0");
    assert!(!text.starts_with("void f("), "{text}");
    assert_eq!(relifted, 0);
}

/// The seal's fold, asked once at the lift that gave the effect, stands for the site's format.
#[test]
fn a_format_only_the_seal_folds_is_read_from_the_lift_that_gave_the_effect() {
    let (text, relifted) = rendered_f(&SEALED, b"%d\n\0");
    assert!(text.starts_with("void f("), "{text}");
    assert_eq!(relifted, 0);
}
