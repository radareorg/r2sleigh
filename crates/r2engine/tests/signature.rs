//! `afi` and the rendered header state each parameter as the one declaration r2types gives it.

mod common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;

/// `mov rax, rdi; ret`, under a name the prototype table declares `strlen(const char *)`.
const RETURNS_ITS_ARGUMENT: &[u8] = &[0x48, 0x89, 0xf8, 0xc3];

#[test]
fn afi_and_the_header_declare_a_parameter_alike() {
    let code = RETURNS_ITS_ARGUMENT;
    let mut program = OpenProgram::of(Literal::of_code(
        code,
        &[("strlen", BASE, code.len() as u64)],
    ));
    let info = program.function_info(BASE).expect("it is described");
    let rendered = program
        .rendered(BASE, r2engine::RenderTier::C)
        .expect("it renders")
        .response
        .output
        .into_text();
    let header = rendered.lines().next().expect("a header");
    let declared = info
        .arguments
        .iter()
        .map(|argument| r2types::c_object_declaration(&argument.ty, "_"))
        .collect::<Vec<_>>();
    // The declaration's `const` lives on the signature, not on the type graph the parameter entity carries.
    assert_eq!(declared, ["const int8_t* _"], "{header}");
    let (_, parameters) = header.split_once('(').expect("a parameter list");
    let (ty, _) = parameters
        .trim_end_matches(')')
        .rsplit_once(' ')
        .expect("a typed parameter");
    assert_eq!(format!("{ty} _"), declared[0], "{header}");
    assert!(info.returns.is_some(), "afi decides no return for {header}");
}
