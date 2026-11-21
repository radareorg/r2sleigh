//! What a rendering reads from the open program: names, and text in its data.

use crate::common;

use common::{BASE, CALLER, GLIBC, Literal, ONE, STUB, TEXT, TWO, opened};
use r2engine::program::OpenProgram;

fn c_of(program: &mut OpenProgram<Literal>, entry: u64) -> String {
    program
        .rendered(entry)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// `lea rdi, [address]; call puts; ret`, written over `two`.
fn putting(address: u64) -> Vec<u8> {
    let disp = i32::try_from(address as i64 - (TWO + 7) as i64).expect("near");
    let mut code = vec![0x48, 0x8d, 0x3d];
    code.extend_from_slice(&disp.to_le_bytes());
    let rel = i32::try_from(STUB as i64 - (TWO + 12) as i64).expect("near");
    code.push(0xe8);
    code.extend_from_slice(&rel.to_le_bytes());
    code.push(0xc3);
    code
}

#[test]
fn a_call_is_spelled_by_the_name_the_container_gives_its_target() {
    let c = c_of(&mut opened(), CALLER);
    assert!(c.contains("one()"), "{c}");
}

#[test]
fn a_call_to_an_import_declared_never_to_return_ends_the_function() {
    // `exit` is declared by each C library, so the program states which it runs on.
    let mut program = OpenProgram::of(Literal::new().importing("exit").running_on(GLIBC));
    // mov edi, 1; call exit; mov eax, 7; ret -- the last two are never reached.
    let call = i32::try_from(STUB as i64 - (TWO + 10) as i64).expect("near");
    let mut code = vec![0xbf, 0x01, 0, 0, 0, 0xe8];
    code.extend_from_slice(&call.to_le_bytes());
    code.extend_from_slice(&[0xb8, 0x07, 0, 0, 0, 0xc3]);
    program.source_mut().write(TWO, &code);
    let c = c_of(&mut program, TWO);
    assert!(c.contains("exit(1)"), "{c}");
    assert!(c.contains("__attribute__((noreturn)) void exit("), "{c}");
    let returns = c
        .lines()
        .any(|line| line.trim_start().starts_with("return"));
    assert!(!returns, "{c}");
}

#[test]
fn an_arm_ending_in_a_call_declared_never_to_return_is_a_conjunction_that_leaves_by_it() {
    // `test edi, edi; jne no; test esi, esi; jne no; mov edi, 1; call exit; no: xor eax, eax; ret`: the
    // arm that calls `exit` ends control, so the certificate must read it so, at each stage and at the end.
    let mut program = OpenProgram::of(Literal::new().importing("exit").running_on(GLIBC));
    let call = i32::try_from(STUB as i64 - (TWO + 18) as i64).expect("near");
    let mut code = vec![
        0x85, 0xff, 0x75, 0x0e, 0x85, 0xf6, 0x75, 0x0a, 0xbf, 0x01, 0, 0, 0, 0xe8,
    ];
    code.extend_from_slice(&call.to_le_bytes());
    code.extend_from_slice(&[0x31, 0xc0, 0xc3]);
    program.source_mut().write(TWO, &code);
    let c = c_of(&mut program, TWO);
    assert!(!c.contains("r2sleigh refused"), "{c}");
    let tests: Vec<_> = c
        .lines()
        .filter(|line| line.trim_start().starts_with("if "))
        .collect();
    assert_eq!(tests.len(), 1, "{c}");
    assert!(tests[0].contains(" && ") && !c.contains("goto"), "{c}");
    assert!(c.contains("exit(1)"), "{c}");
}

/// `g: jmp t` then `t: lea eax, [rdi + rdi*2 + 1]; ret`, each a stated function.
const TAIL_JUMPING: &[u8] = &[
    0xe9, 0x0b, 0x00, 0x00, 0x00, // g: jmp t
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // padding
    0x8d, 0x44, 0x7f, 0x01, // t: lea eax, [rdi + rdi*2 + 1]
    0xc3, // ret
];

/// Where a jump sends control is executed, not read, so the function it lands
/// on is no data the jumping one names: `g` is `g`, calling `t` in its tail,
/// and not the import stub of a symbol `t` it only reached by name.
#[test]
fn a_tail_jump_to_a_defined_function_is_a_call_to_it_and_no_import() {
    let (g, t) = (BASE, BASE + 0x10);
    let mut program = OpenProgram::of(Literal::of_code(TAIL_JUMPING, &[("g", g, 5), ("t", t, 5)]));
    let c = c_of(&mut program, g);
    let head = c.lines().next().unwrap_or_default();
    assert!(head.contains(" g(") && !head.contains(" t("), "{c}");
    let tail_call = |line: &str| line.trim_start().starts_with("return") && line.contains(")t(");
    assert!(c.lines().any(tail_call), "{c}");
    assert!(!c.contains("import stub"), "{c}");
}

#[test]
fn text_in_a_data_section_is_a_string_and_text_in_code_is_not() {
    let mut program = OpenProgram::of(Literal::new().with_data().importing("puts"));
    program.source_mut().write(TEXT, b"hello\0");
    program.source_mut().write(TWO, &putting(TEXT));
    let c = c_of(&mut program, TWO);
    // The one argument is the literal, at whatever conversion to `const char*` the pipeline spells.
    let arguments = common::call_arguments(&c, "puts").expect("a call to puts");
    assert_eq!(
        arguments
            .iter()
            .map(|a| common::bare(a))
            .collect::<Vec<_>>(),
        ["\"hello\""],
        "{c}"
    );

    // The same bytes in the padding after `one`, which is code, not data,
    // and just past the data section's end, which is no section at all.
    for elsewhere in [ONE + 6, TEXT + 8] {
        program.source_mut().write(elsewhere, b"hello\0");
        program.source_mut().write(TWO, &putting(elsewhere));
        let c = c_of(&mut program, TWO);
        assert!(c.contains("puts(") && !c.contains("\"hello\""), "{c}");
    }
}

#[test]
fn an_address_no_instruction_can_run_at_is_refused_rather_than_rendered_as_a_function() {
    // `t` is stated a function and its bytes decode, `"1"` as `xor [rax],
    // eax`, yet the program maps them as data. `s 0x2020; pdd` on a stripped
    // binary rendered .rodata as `void fcn_2020(void)` with a clean proof line.
    let data = common::transferring()
        .with_data_after(common::TRANSFERRED)
        .data_mapped_after(common::TRANSFERRED);
    let mut program = OpenProgram::of(data);
    let rendering = (program.rendered(common::TRANSFERRED)).expect("a refusal is a record");
    let refused = (rendering.refused.clone()).expect("data was rendered as a function");
    assert_eq!(
        refused.to_string(),
        "no instruction can run at 0x1100: the program maps it without execute permission"
    );
    assert_eq!(refused.kind(), "walk");
    // The record is what `pdd` prints, and `pddj` carries the same reason.
    let text = rendering.response.output.text().to_owned();
    assert!(text.contains(&refused.to_string()), "{text}");
    let answer = rendering.answer("t", common::TRANSFERRED);
    let json = answer.refused.expect("pddj carries the refusal");
    assert_eq!((json.kind, json.reason), ("walk", refused.to_string()));
    // The code that calls it is still code, and still renders.
    let c = c_of(&mut program, BASE);
    assert!(c.contains(" f("), "{c}");
}

#[test]
fn a_pointer_stepped_in_a_loop_is_one_carrier_its_update_writes() {
    // l: add al, [rdi]; add rdi, 1; cmp rsi, rdi; jne l; ret
    let mut program = opened();
    let code = [
        0x02, 0x07, 0x48, 0x83, 0xc7, 0x01, 0x48, 0x39, 0xfe, 0x75, 0xf5, 0xc3,
    ];
    program.source_mut().write(TWO, &code);
    let c = c_of(&mut program, TWO);
    assert!(!c.contains("rdi_2"), "{c}");
    assert!(
        c.contains("rdi_1 = (uint64_t)((uint64_t)rdi_1 + (uint64_t)1U);"),
        "{c}"
    );
}
