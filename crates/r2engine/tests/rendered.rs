//! What a rendering reads from the open program: names, and text in its data.

mod common;

use common::{CALLER, Literal, ONE, STUB, TEXT, TWO, opened};
use r2engine::RenderTier;
use r2engine::program::OpenProgram;

fn c_of(program: &mut OpenProgram<Literal>, entry: u64) -> String {
    program
        .rendered(entry, RenderTier::C)
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
    let mut program = OpenProgram::of(Literal::new().importing("exit"));
    // mov edi, 1; call exit; mov eax, 7; ret -- the last two are never reached.
    let call = i32::try_from(STUB as i64 - (TWO + 10) as i64).expect("near");
    let mut code = vec![0xbf, 0x01, 0, 0, 0, 0xe8];
    code.extend_from_slice(&call.to_le_bytes());
    code.extend_from_slice(&[0xb8, 0x07, 0, 0, 0, 0xc3]);
    program.source_mut().write(TWO, &code);
    let c = c_of(&mut program, TWO);
    assert!(c.contains("exit(1)"), "{c}");
    assert!(!c.contains("return"), "{c}");
}

#[test]
fn text_in_a_data_section_is_a_string_and_text_in_code_is_not() {
    let mut program = OpenProgram::of(Literal::new().with_data().importing("puts"));
    program.source_mut().write(TEXT, b"hello\0");
    program.source_mut().write(TWO, &putting(TEXT));
    let c = c_of(&mut program, TWO);
    assert!(c.contains("puts((const int8_t*)\"hello\")"), "{c}");

    // The same bytes in the padding after `one`, which is code, not data,
    // and just past the data section's end, which is no section at all.
    for elsewhere in [ONE + 6, TEXT + 8] {
        program.source_mut().write(elsewhere, b"hello\0");
        program.source_mut().write(TWO, &putting(elsewhere));
        let c = c_of(&mut program, TWO);
        assert!(c.contains("puts(") && !c.contains("\"hello\""), "{c}");
    }
}
