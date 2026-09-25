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

/// `sub rsp, 8; call rdi; add rsp, 8; ret`: it returns whatever the function
/// it was handed returns, which nothing here proves.
const RETURNS_WHAT_IT_CALLS: &[u8] = &[
    0x48, 0x83, 0xec, 0x08, // sub rsp, 8
    0xff, 0xd7, // call rdi
    0x48, 0x83, 0xc4, 0x08, // add rsp, 8
    0xc3, // ret
];

/// An unproven return is one fact, and both views state it: `afi` and the
/// rendered header declare the same result carrier, `afi` says the value is
/// unproven, and the definition hands back a residual of that carrier. The
/// renderer decides no type of its own.
#[test]
fn afi_and_the_header_declare_an_unproven_return_alike() {
    let code = RETURNS_WHAT_IT_CALLS;
    let mut program = OpenProgram::of(Literal::of_code(
        code,
        &[("forward", BASE, code.len() as u64)],
    ));
    let info = program.function_info(BASE).expect("it is described");
    let rendered = program
        .rendered(BASE, r2engine::RenderTier::C)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(info.return_unproven, "{info:?}\n{rendered}");
    let declared = info.returns.as_ref().expect("the carrier is declared");
    assert_eq!(declared.to_string(), "uint64_t", "{rendered}");
    let header = rendered.lines().next().expect("a header");
    assert!(
        header.starts_with(&format!("{declared} forward(")),
        "{header}"
    );
    assert!(
        rendered.contains("return r2sleigh_residual_u64("),
        "{rendered}"
    );
}
