//! A function's convention is what its debug information states (clang's `ms_abi`, `sysv_abi`),
//! the target's default otherwise (doc/adr-call-boundary.md, "S20 as built").

use crate::common;

use common::{BASE, Literal};
use r2abi::StatedConvention;
use r2engine::program::OpenProgram;

/// `ms_abi long diff(long a, long b) { return a - b; }` at clang `-O1`, then SysV `twice(a, b)
/// { return diff(b, a) * 2; }`: r2image's `dwarf_ms_abi.c` with the call's arguments swapped.
const DIFF_AND_TWICE: &[u8] = &[
    0x48, 0x89, 0xc8, // 1000 mov rax, rcx
    0x48, 0x29, 0xd0, // 1003 sub rax, rdx
    0xc3, // 1006 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1007 padding
    0x48, 0x83, 0xec,
    0x28, // 1010 sub rsp, 0x28: the home area Microsoft x64 gives the callee
    0x48, 0x89, 0xfa, // 1014 mov rdx, rdi
    0x48, 0x89, 0xf1, // 1017 mov rcx, rsi
    0xe8, 0xe1, 0xff, 0xff, 0xff, // 101a call 0x1000
    0x48, 0x01, 0xc0, // 101f add rax, rax
    0x48, 0x83, 0xc4, 0x28, // 1022 add rsp, 0x28
    0xc3, // 1026 ret
];

const TWICE: u64 = BASE + 0x10;

/// What the debug information states of `diff`: `long diff(long a, long b)` under `stated`.
fn declaring(stated: StatedConvention) -> r2abi::Declarations {
    use r2abi::{Parameter, Prototype, Scalar, ScalarKind, Type, TypeGraph, Width};
    let mut graph = TypeGraph::new();
    let long = graph.add(Type::Scalar(Scalar {
        kind: ScalarKind::Signed,
        width: Width::Bits(64),
        name: Some("long int".to_owned()),
    }));
    let prototype = Prototype {
        name: "diff".to_owned(),
        parameters: vec![
            Parameter::new(long, "long", Some("a")),
            Parameter::new(long, "long", Some("b")),
        ],
        returns: "long".into(),
        return_type: long,
        convention: stated,
        ..Prototype::default()
    };
    let mut declarations = r2abi::Declarations::new(graph);
    declarations.declare_function(BASE, prototype);
    declarations
}

fn program(stated: StatedConvention) -> OpenProgram<Literal> {
    let functions = [("diff", BASE, 7), ("twice", TWICE, 0x17)];
    OpenProgram::of(
        Literal::of_code(DIFF_AND_TWICE, &functions).with_declarations(declaring(stated)),
    )
}

/// `diff` under `sysv_abi` in a PE, and a Microsoft x64 `keeps(a, b, f)` holding `a` across a
/// call through r8 in rsi, which Microsoft x64 preserves and SysV does not.
const SYSV_IN_A_PE: &[u8] = &[
    0x48, 0x89, 0xf8, // 1000 mov rax, rdi
    0x48, 0x29, 0xf0, // 1003 sub rax, rsi
    0xc3, // 1006 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1007 padding
    0x48, 0x83, 0xec, 0x28, // 1010 sub rsp, 0x28
    0x48, 0x89, 0xce, // 1014 mov rsi, rcx
    0x48, 0x89, 0xd7, // 1017 mov rdi, rdx
    0x41, 0xff, 0xd0, // 101a call r8
    0x66, 0x90, // 101d nop
    0x48, 0x01, 0xf0, // 101f add rax, rsi
    0x48, 0x83, 0xc4, 0x28, // 1022 add rsp, 0x28
    0xc3, // 1026 ret
];

fn pe(stated: StatedConvention) -> OpenProgram<Literal> {
    let functions = [("diff", BASE, 7), ("keeps", TWICE, 0x17)];
    let program = Literal::of_code(SYSV_IN_A_PE, &functions).with_declarations(declaring(stated));
    OpenProgram::of(program.pe())
}

/// The register of this name, in the machine's coordinates.
fn register(
    target: &r2engine::native::NativeTarget<'_>,
    name: &str,
) -> r2source::CanonicalStorageId {
    let found = (target.arch.registers.iter()).find(|it| it.name.eq_ignore_ascii_case(name));
    let found = found.unwrap_or_else(|| panic!("{name}"));
    r2source::CanonicalStorageId {
        space: r2source::CanonicalStorageSpace::Register,
        offset: found.offset,
        size: found.size,
    }
}

fn rendered(open: &mut OpenProgram<Literal>, at: u64) -> String {
    open.rendered(at)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// The register a declared parameter arrives in, by the name the machine gives it.
fn arriving(open: &mut OpenProgram<Literal>) -> Vec<String> {
    let info = open.function_info(BASE).expect("it is described");
    let target = r2engine::native::Program::target_at(open, BASE).expect("a machine");
    (info.arguments.iter())
        .map(|argument| {
            let storage = argument.storage.expect("a register");
            let named = target.arch.registers.iter().find(|register| {
                register.offset == storage.offset && register.size == storage.size
            });
            named.map_or_else(|| format!("{storage:?}"), |r| r.name.to_lowercase())
        })
        .collect()
}

/// An ELF function stated `ms_abi` takes its parameters in rcx and rdx; under the target's SysV
/// they were rdi and rsi, which the body never reads.
#[test]
fn an_ms_abi_function_in_an_elf_places_rcx_first() {
    let mut open = program(StatedConvention::LlvmWin64);
    assert_eq!(arriving(&mut open), ["rcx", "rdx"]);
    // `afi` names the interface's convention (D275).
    let convention = |open: &mut OpenProgram<Literal>| open.function_info(BASE).ok()?.convention;
    assert_eq!(convention(&mut open), Some(r2abi::ConventionId::Win64));
    let text = rendered(&mut open, BASE);
    assert!(text.contains("(uint64_t)a - (uint64_t)b"), "{text}");
    assert!(!text.contains("r2sleigh_residual"), "{text}");
    // Unstated, the same declaration is placed in rdi and rsi, where the body reads nothing.
    let mut unstated = program(StatedConvention::Normal);
    assert_eq!(arriving(&mut unstated), ["rdi", "rsi"]);
    assert_eq!(
        convention(&mut unstated),
        Some(r2abi::ConventionId::SysVAmd64)
    );
}

/// The SysV caller passes `diff(b, a)` in rcx and rdx, the callee's own locations; read as
/// rdi and rsi it would be `diff(a, b)`.
#[test]
fn a_sysv_caller_passes_an_ms_abi_callee_its_own_registers() {
    let mut open = program(StatedConvention::LlvmWin64);
    open.analyse_program().expect("aa");
    let text = rendered(&mut open, TWICE);
    assert!(
        text.contains("diff((int64_t)arg1, (int64_t)arg0)"),
        "{text}"
    );
    let mut unstated = program(StatedConvention::Normal);
    unstated.analyse_program().expect("aa");
    let text = rendered(&mut unstated, TWICE);
    assert!(
        text.contains("diff((int64_t)arg0, (int64_t)arg1)"),
        "{text}"
    );
}

/// A code no model here has refuses the function, and nothing places it under the default.
#[test]
fn an_unmodelled_stated_convention_refuses_the_function() {
    // `DW_CC_LLVM_vectorcall` (0xc0).
    let mut open = program(StatedConvention::Other(0xc0));
    let info = open.function_info(BASE).expect("it is described");
    let refused = info.refused.map(|why| why.to_string()).unwrap_or_default();
    assert!(refused.contains("no model has"), "{refused}");
    // The SysV function beside it states nothing, so the default places it.
    assert!(
        open.function_info(TWICE)
            .expect("described")
            .refused
            .is_none()
    );
}

/// An import's row is placed under the program's convention, which its library runs under:
/// `puts` called from the `ms_abi` function still takes rdi, and the call reads no rcx for it.
#[test]
fn an_import_called_under_ms_abi_is_placed_under_the_program_s_convention() {
    let open = program(StatedConvention::LlvmWin64);
    let target = r2engine::native::Program::target_at(&open, BASE).expect("a machine");
    let reads = r2engine::native::import_reads(&target, "puts").expect("puts binds");
    let names = (reads.registers.iter().take(1))
        .filter_map(|storage| {
            (target.arch.registers.iter())
                .find(|it| it.offset == storage.offset && it.size == storage.size)
                .map(|it| it.name.to_lowercase())
        })
        .collect::<Vec<_>>();
    assert_eq!(names, ["rdi"]);
}

/// In a PE stating a `sysv_abi` function no site states its callee's convention, so rsi survives
/// no indirect call from a Microsoft x64 function; with nothing stated it does.
#[test]
fn a_call_in_a_program_stating_sysv_abi_keeps_no_register_sysv_clobbers() {
    let mut open = pe(StatedConvention::LlvmX8664SysV);
    assert_eq!(arriving(&mut open), ["rdi", "rsi"]);
    let target = r2engine::native::Program::target_at(&open, TWICE).expect("a machine");
    let effect = &*target.call;
    for name in ["rsi", "rdi", "xmm6"] {
        assert!(effect.clobbers(register(&target, name)), "{name}");
    }
    assert!(effect.preserves(register(&target, "rbx")));
    let reads = effect.call_reads().expect("the join's reads");
    assert!(reads.contains(&register(&target, "rdi")), "SysV's first");
    // `add rax, rsi` past the call reads an rsi the call may have written, never `a`.
    let text = rendered(&mut open, TWICE);
    assert!(!text.contains("+ (uint64_t)arg0"), "{text}");
    let mut unstated = pe(StatedConvention::Normal);
    let target = r2engine::native::Program::target_at(&unstated, TWICE).expect("a machine");
    let effect = &*target.call;
    assert!(effect.preserves(register(&target, "rsi")));
    let text = rendered(&mut unstated, TWICE);
    assert!(text.contains("+ (uint64_t)arg0"), "{text}");
}

/// `diff` under `sysv_abi` in a PE, its body writing rsi (`xor esi, esi`), called directly by a
/// Microsoft x64 `keeps(a, b)` that reads rsi past the call.
const SYSV_WRITES_RSI: &[u8] = &[
    0x48, 0x89, 0xf8, // 1000 mov rax, rdi
    0x48, 0x29, 0xf0, // 1003 sub rax, rsi
    0x31, 0xf6, // 1006 xor esi, esi
    0xc3, // 1008 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1009 padding
    0x48, 0x83, 0xec, 0x28, // 1010 sub rsp, 0x28
    0x48, 0x89, 0xce, // 1014 mov rsi, rcx
    0x48, 0x89, 0xd7, // 1017 mov rdi, rdx
    0xe8, 0xe1, 0xff, 0xff, 0xff, // 101a call 0x1000
    0x48, 0x01, 0xf0, // 101f add rax, rsi
    0x48, 0x83, 0xc4, 0x28, // 1022 add rsp, 0x28
    0xc3, // 1026 ret
];

/// A direct call's kills are its callee's: the `sysv_abi` body writes rsi, so the caller's
/// `add rax, rsi` reads no `a`, under `aa` and cold.
#[test]
fn a_direct_call_to_a_sysv_abi_callee_kills_what_its_body_writes() {
    let functions = [("diff", BASE, 9), ("keeps", TWICE, 0x17)];
    let stated = declaring(StatedConvention::LlvmX8664SysV);
    let program = Literal::of_code(SYSV_WRITES_RSI, &functions).with_declarations(stated);
    let mut open = OpenProgram::of(program.pe());
    let cold = rendered(&mut open, TWICE);
    assert!(!cold.contains("+ (uint64_t)arg0"), "{cold}");
    open.analyse_program().expect("aa");
    let text = rendered(&mut open, TWICE);
    assert!(!text.contains("+ (uint64_t)arg0"), "{text}");
}

/// `mov [rdi], esi; ret`: the body GCC leaves of `int store(int *p, int v)` once IPA-SRA drops a
/// result no caller reads (find `visit_open_fds.constprop.0.isra.0`): no return defines RAX.
const RESULT_DROPPED: &[u8] = &[
    0x89, 0x37, // 1000 mov [rdi], esi
    0xc3, // 1002 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1003 padding
    0x89, 0x37, // 1010 mov [rdi], esi
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1012 mov eax, 7
    0xc3, // 1017 ret
];

/// `store` declared `returns store(int *p, int v)` at `BASE` and at `TWICE`, where the second
/// body writes EAX.
fn storing(returns: Option<&str>) -> OpenProgram<Literal> {
    use r2abi::{Parameter, Prototype, Scalar, ScalarKind, Type, TypeGraph, TypeId, Width};
    let mut graph = TypeGraph::new();
    let int = graph.add(Type::Scalar(Scalar {
        kind: ScalarKind::Signed,
        width: Width::Bits(32),
        name: Some("int".to_owned()),
    }));
    let pointer = graph.add(Type::Pointer { target: int });
    let prototype = |name: &str| Prototype {
        name: name.to_owned(),
        parameters: vec![
            Parameter::new(pointer, "int *", Some("p")),
            Parameter::new(int, "int", Some("v")),
        ],
        returns: returns.unwrap_or("void").into(),
        return_type: returns.map_or(TypeId::VOID, |_| int),
        ..Prototype::default()
    };
    let mut declarations = r2abi::Declarations::new(graph);
    declarations.declare_function(BASE, prototype("store"));
    declarations.declare_function(TWICE, prototype("store_seven"));
    let functions = [("store", BASE, 3), ("store_seven", TWICE, 8)];
    OpenProgram::of(Literal::of_code(RESULT_DROPPED, &functions).with_declarations(declarations))
}

const KEPT_AGAINST_THE_BODY: &str = "the declared result is kept against the body";

/// DWARF states `int` and no return defines RAX: the declaration stays, the return is a residual
/// and the proof line names the disputed lane, cold and under `aa` (D331).
#[test]
fn a_declared_result_no_return_defines_keeps_its_type_and_disputes_the_body() {
    for closed in [false, true] {
        let mut open = storing(Some("int"));
        if closed {
            open.analyse_program().expect("aa");
        }
        let text = rendered(&mut open, BASE);
        assert!(
            text.contains("int32_t store(int32_t* p, int32_t v)"),
            "{text}"
        );
        let clause = format!("{KEPT_AGAINST_THE_BODY}: no return defines the integer result");
        assert!(text.contains(&clause), "{closed}: {text}");
        assert!(text.contains("return r2sleigh_residual_"), "{text}");
        // A body that writes the declared lane disputes nothing.
        let text = rendered(&mut open, TWICE);
        assert!(text.contains("int32_t store_seven("), "{text}");
        assert!(!text.contains(KEPT_AGAINST_THE_BODY), "{text}");
    }
}

/// DWARF states `void`, and a return leaves a value the body defines in RAX: `void` stays, and
/// the proof line names the written lane. A body that leaves RAX alone disputes nothing.
#[test]
fn a_declared_void_whose_body_writes_a_result_lane_stays_void_and_names_the_lane() {
    let mut open = storing(None);
    let text = rendered(&mut open, TWICE);
    assert!(
        text.contains("void store_seven(int32_t* p, int32_t v)"),
        "{text}"
    );
    let clause = format!("{KEPT_AGAINST_THE_BODY}: a return defines the integer result");
    assert!(text.contains(&clause), "{text}");
    let text = rendered(&mut open, BASE);
    assert!(text.contains("void store(int32_t* p, int32_t v)"), "{text}");
    assert!(!text.contains(KEPT_AGAINST_THE_BODY), "{text}");
}

/// `diff` under `sysv_abi` in a PE, and a Microsoft x64 `keeps(a)` holding `a` in rsi across a
/// call to an import, then adding it to the import's result.
const KEEPS_ACROSS_AN_IMPORT: &[u8] = &{
    let mut code = [0xccu8; 0xa0];
    let body: &[u8] = &[
        0x48, 0x89, 0xf8, // 1000 mov rax, rdi
        0x48, 0x29, 0xf0, // 1003 sub rax, rsi
        0xc3, // 1006 ret
    ];
    let keeps: &[u8] = &[
        0x48, 0x83, 0xec, 0x28, // 1010 sub rsp, 0x28
        0x48, 0x89, 0xce, // 1014 mov rsi, rcx
        0xe8, 0x74, 0x00, 0x00, 0x00, // 1017 call 0x1090: the import's stub
        0x48, 0x01, 0xf0, // 101c add rax, rsi
        0x48, 0x83, 0xc4, 0x28, // 101f add rsp, 0x28
        0xc3, // 1023 ret
    ];
    let stub: &[u8] = &[0xff, 0x25, 0x02, 0x00, 0x00, 0x00]; // 1090 jmp [rip + 2]
    let mut at = 0;
    while at < body.len() {
        code[at] = body[at];
        at += 1;
    }
    at = 0;
    while at < keeps.len() {
        code[0x10 + at] = keeps[at];
        at += 1;
    }
    at = 0;
    while at < stub.len() {
        code[0x90 + at] = stub[at];
        at += 1;
    }
    at = 0x98;
    while at < 0xa0 {
        code[at] = 0;
        at += 1;
    }
    code
};

fn importing_pe(dll: &str) -> OpenProgram<Literal> {
    let functions = [("diff", BASE, 7), ("keeps", TWICE, 0x14)];
    let program = Literal::of_code(KEEPS_ACROSS_AN_IMPORT, &functions)
        .with_declarations(declaring(StatedConvention::LlvmX8664SysV))
        .importing_from(dll, "GetLastError")
        .pe();
    OpenProgram::of(program)
}

/// A bound import runs under the default, Microsoft x64, which keeps rsi though the stated SysV
/// function clobbers it; an import no table binds runs under the join and keeps no rsi (D252).
#[test]
fn a_pe_stating_one_sysv_function_keeps_rsi_across_a_kernel32_call() {
    let mut bound = importing_pe("KERNEL32.dll");
    let text = rendered(&mut bound, TWICE);
    assert!(text.contains("arg0"), "{text}");
    let mut unbound = importing_pe("foo.dll");
    let text = rendered(&mut unbound, TWICE);
    assert!(!text.contains("arg0"), "{text}");
}
