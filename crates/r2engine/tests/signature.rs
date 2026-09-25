//! `afi` and the rendered header state each parameter as the one declaration r2types gives it.

mod common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;

/// `mov rax, rdi; ret`.
const RETURNS_ITS_ARGUMENT: &[u8] = &[0x48, 0x89, 0xf8, 0xc3];

/// What a binary's debug information would say of the body at `BASE`:
/// `size_t measured(const char *s)`, stated at that address.
fn measured() -> r2abi::Declarations {
    use r2abi::{Parameter, Prototype, Qualifiers, Scalar, ScalarKind, Type, TypeGraph, Width};
    let mut graph = TypeGraph::new();
    let scalar = |kind, bits, name: &str| {
        Type::Scalar(Scalar {
            kind,
            width: Width::Bits(bits),
            name: Some(name.to_owned()),
        })
    };
    let char_ = graph.add(scalar(ScalarKind::Signed, 8, "char"));
    let constant = graph.add(Type::Qualified {
        qualifiers: Qualifiers::CONST,
        target: char_,
    });
    let pointer = graph.add(Type::Pointer { target: constant });
    let unsigned_long = graph.add(scalar(ScalarKind::Unsigned, 64, "long unsigned int"));
    let size = graph.add(Type::Typedef {
        name: "size_t".to_owned(),
        target: unsigned_long,
    });
    let prototype = Prototype {
        name: "measured".to_owned(),
        parameters: vec![Parameter::new(pointer, "const char *", Some("s"))],
        returns: "size_t".into(),
        return_type: size,
        ..Prototype::default()
    };
    let mut declarations = r2abi::Declarations::new(graph);
    declarations.declare_function(BASE, prototype);
    declarations
}

#[test]
fn afi_and_the_header_declare_a_parameter_alike() {
    let code = RETURNS_ITS_ARGUMENT;
    let mut program = OpenProgram::of(
        Literal::of_code(code, &[("measured", BASE, code.len() as u64)])
            .with_declarations(measured()),
    );
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

/// A body the program calls `strlen` is the program's own, and the library
/// table's `strlen(const char *)` is a statement about an import. Found by
/// name, it typed this body's parameter as a string it never reads as one;
/// found by address, nothing declares the body and its parameter is what the
/// body proves: all sixty-four bits of `rdi`, returned whole.
#[test]
fn a_body_named_after_a_library_function_takes_nothing_from_the_table() {
    let code = RETURNS_ITS_ARGUMENT;
    let mut program = OpenProgram::of(Literal::of_code(
        code,
        &[("strlen", BASE, code.len() as u64)],
    ));
    let info = program.function_info(BASE).expect("it is described");
    let declared = info
        .arguments
        .iter()
        .map(|argument| r2types::c_object_declaration(&argument.ty, "_"))
        .collect::<Vec<_>>();
    assert_eq!(declared, ["uint64_t _"]);
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
