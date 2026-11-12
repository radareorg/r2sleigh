//! `afi` and the rendered header state each parameter as the one declaration r2types gives it.

use crate::common;

use r2engine::discovery::Basis;

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
        .rendered(BASE)
        .expect("it renders")
        .response
        .output
        .into_text();
    let header = rendered.lines().next().expect("a header");
    let declared = info
        .arguments
        .iter()
        .map(|argument| r2types::c_object_declaration(&argument.ty.value, "_"))
        .collect::<Vec<_>>();
    // The declaration's `const` lives on the signature, not on the type graph the parameter entity carries.
    assert_eq!(declared, ["const char* _"], "{header}");
    let (_, parameters) = header.split_once('(').expect("a parameter list");
    let (ty, _) = parameters
        .trim_end_matches(')')
        .rsplit_once(' ')
        .expect("a typed parameter");
    assert_eq!(format!("{ty} _"), declared[0], "{header}");
    assert!(info.returns.is_some(), "afi decides no return for {header}");
    // Both rest on the program's own declaration.
    let bases = (info
        .arguments
        .iter()
        .map(|argument| argument.ty.confidence.basis))
    .chain(info.returns.iter().map(|returns| returns.confidence.basis))
    .collect::<Vec<_>>();
    assert_eq!(bases, [Basis::DebugInfo, Basis::DebugInfo], "{header}");
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
        .map(|argument| r2types::c_object_declaration(&argument.ty.value, "_"))
        .collect::<Vec<_>>();
    assert_eq!(declared, ["uint64_t _"]);
    // Recovered, so nothing declares it: the type is no more than the body's reading of it.
    let bases = (info.arguments.iter()).map(|argument| argument.ty.confidence.basis);
    assert_eq!(bases.collect::<Vec<_>>(), [Basis::CarrierWidth]);
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
        .rendered(BASE)
        .expect("it renders")
        .response
        .output
        .into_text();
    let returns = info.returns.as_ref().expect("a return is stated");
    assert_eq!(
        returns.confidence.basis,
        Basis::Convention,
        "{info:?}\n{rendered}"
    );
    let declared = returns.value.as_ref().expect("the carrier is declared");
    assert_eq!(declared.to_string(), "uint64_t", "{rendered}");
    // The header spells the same carrier through the prelude typedef, which claims no C type (D201).
    let header = rendered.lines().next().expect("a header");
    assert!(
        header.starts_with("r2sleigh_result_u64 forward("),
        "{header}"
    );
    let unproven = info.unproven.expect("afi names the unproven result");
    assert_eq!(unproven.cause_name(), "Written", "{rendered}");
    assert!(
        rendered.contains("the result is unproven (Written)"),
        "{rendered}"
    );
    assert!(
        rendered.contains("return r2sleigh_residual_u64("),
        "{rendered}"
    );
}

/// `mov eax, [rdi]; ret`: the body reads through `rdi`, so its recovered parameter is a pointer,
/// and that type rests on the dereference that proves it, not on the carrier's width.
#[test]
fn a_parameter_the_body_reads_through_rests_on_the_dereference() {
    let code: &[u8] = &[0x8b, 0x07, 0xc3];
    let mut program = OpenProgram::of(Literal::of_code(code, &[("load", BASE, code.len() as u64)]));
    let info = program.function_info(BASE).expect("it is described");
    let declared = (info.arguments.iter())
        .map(|argument| r2types::c_object_declaration(&argument.ty.value, "_"))
        .collect::<Vec<_>>();
    assert_eq!(declared, ["uint32_t* _"]);
    let bases = (info.arguments.iter()).map(|argument| argument.ty.confidence.basis);
    assert_eq!(bases.collect::<Vec<_>>(), [Basis::Dereferenced]);
}

/// AArch64: `caller` is `x0 = import(x0) + 1` through a stub at 0x1020 whose slot is 0x1040
/// (a lone stub without glibc's `add x16`, which would start its cell at the `br`).
const A64_CALLS_THROUGH_A_STUB: &[u8] = &[
    0xfd, 0x7b, 0xbf, 0xa9, // 1000 stp x29, x30, [sp, #-16]!
    0xfd, 0x03, 0x00, 0x91, // 1004 mov x29, sp
    0x06, 0x00, 0x00, 0x94, // 1008 bl 0x1020
    0x00, 0x04, 0x00, 0x91, // 100c add x0, x0, #1
    0xfd, 0x7b, 0xc1, 0xa8, // 1010 ldp x29, x30, [sp], #16
    0xc0, 0x03, 0x5f, 0xd6, // 1014 ret
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, // 1018 nop; nop
    0x10, 0x00, 0x00, 0x90, // 1020 adrp x16, 0x1000
    0x11, 0x22, 0x40, 0xf9, // 1024 ldr x17, [x16, #0x40]
    0x20, 0x02, 0x1f, 0xd6, // 1028 br x17
    0x1f, 0x20, 0x03, 0xd5, // 102c nop
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03,
    0xd5, // 1030 padding
    0, 0, 0, 0, 0, 0, 0, 0, // 1040 the slot
];

/// The callee's declaration as `caller`'s rendering states it, on glibc or on no stated library.
fn a64_declared(import: &str, glibc: bool) -> String {
    let program = Literal::of_code(A64_CALLS_THROUGH_A_STUB, &[("caller", BASE, 0x18)])
        .in_aarch64()
        .importing_through(BASE + 0x20..BASE + 0x30, BASE + 0x40, import);
    let program = match glibc {
        true => program.running_on(common::GLIBC),
        false => program,
    };
    let text = OpenProgram::of(program)
        .rendered(BASE)
        .expect("it renders")
        .response
        .output
        .into_text();
    let declared = text
        .lines()
        .find(|line| line.contains(&format!(" {import}(")) && line.ends_with(");"));
    declared.map(str::trim).unwrap_or(&text).to_owned()
}

/// `x0 = import(x0) + 1` on x86-64 glibc: `call` the stub, `add rax, 1`, `ret`.
fn x86_64_declared(import: &str) -> String {
    let mut program = OpenProgram::of(Literal::new().importing(import).running_on(common::GLIBC));
    let call = i32::try_from(common::STUB as i64 - (common::TWO + 5) as i64).expect("near");
    let mut code = vec![0xe8];
    code.extend_from_slice(&call.to_le_bytes());
    code.extend_from_slice(&[0x48, 0x83, 0xc0, 0x01, 0xc3]);
    program.source_mut().write(common::TWO, &code);
    let text = (program
        .rendered(common::TWO)
        .expect("it renders")
        .response
        .output)
        .into_text();
    let declared = text
        .lines()
        .find(|line| line.contains(&format!(" {import}(")) && line.ends_with(");"));
    declared.map(str::trim).unwrap_or(&text).to_owned()
}

/// A row's `wchar_t` and `char` take the target's sign: unsigned under AAPCS64 glibc, signed
/// under SysV x86-64; with no C library stated, nothing states `wchar_t`, so the pointer to it
/// passes as `void*` (D263).
#[test]
fn a_rows_wchar_t_and_char_are_the_targets() {
    assert_eq!(
        a64_declared("wcslen", true),
        "uint64_t wcslen(const uint32_t*);"
    );
    assert_eq!(
        a64_declared("strlen", true),
        "uint64_t strlen(const char*);"
    );
    assert_eq!(
        x86_64_declared("wcslen"),
        "uint64_t wcslen(const int32_t*);"
    );
    assert_eq!(x86_64_declared("strlen"), "uint64_t strlen(const char*);");
    assert_eq!(
        [a64_declared("wcslen", false), a64_declared("strlen", false)],
        ["uint64_t wcslen(void*);", "uint64_t strlen(const char*);"]
    );
}

/// `movsd xmm0, [rsp + 8]; movsd [rdi], xmm0; ret`: the ninth double stored through the pointer.
const STORES_THE_NINTH_DOUBLE: &[u8] = &[
    0xf2, 0x0f, 0x10, 0x44, 0x24, 0x08, // movsd xmm0, [rsp + 8]
    0xf2, 0x0f, 0x11, 0x07, // movsd [rdi], xmm0
    0xc3, // ret
];

/// `void ninth(double *out, double a, ..., double i)`: under SysV `a` to `h` are in the vector
/// registers and `i` is on the stack.
fn ninth() -> r2abi::Declarations {
    use r2abi::{Parameter, Prototype, Scalar, ScalarKind, Type, TypeGraph, Width};
    let mut graph = TypeGraph::new();
    let double = graph.add(Type::Scalar(Scalar {
        kind: ScalarKind::Float,
        width: Width::Bits(64),
        name: Some("double".to_owned()),
    }));
    let pointer = graph.add(Type::Pointer { target: double });
    let void = graph.add(Type::Void);
    let names = ["a", "b", "c", "d", "e", "f", "g", "h", "i"];
    let doubles = names.map(|name| Parameter::new(double, "double", Some(name)));
    let prototype = Prototype {
        name: "ninth".to_owned(),
        parameters: [Parameter::new(pointer, "double *", Some("out"))]
            .into_iter()
            .chain(doubles)
            .collect(),
        returns: "void".into(),
        return_type: void,
        ..Prototype::default()
    };
    let mut declarations = r2abi::Declarations::new(graph);
    declarations.declare_function(BASE, prototype);
    declarations
}

/// A stack slot carries any class: the declared double there is a parameter beside the register
/// ones, never an integer whose disagreement refuses the whole list.
#[test]
fn a_declared_double_on_the_stack_is_declared_beside_the_register_ones() {
    let code = STORES_THE_NINTH_DOUBLE;
    let literal = Literal::of_code(code, &[("ninth", BASE, code.len() as u64)]);
    let text = (OpenProgram::of(literal.with_declarations(ninth())).rendered(BASE))
        .expect("it renders")
        .response
        .output
        .into_text();
    let header = text.lines().next().unwrap_or_default();
    let parameters = common::parameters(header);
    assert_eq!(parameters.len(), 10, "{text}");
    assert_eq!(
        parameters[9],
        ("double".to_owned(), "i".to_owned()),
        "{text}"
    );
}
