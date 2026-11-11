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
    let text = rendered(&mut open, BASE);
    assert!(text.contains("(uint64_t)a - (uint64_t)b"), "{text}");
    assert!(!text.contains("r2sleigh_residual"), "{text}");
    // Unstated, the same declaration is placed in rdi and rsi, where the body reads nothing.
    let mut unstated = program(StatedConvention::Normal);
    assert_eq!(arriving(&mut unstated), ["rdi", "rsi"]);
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
    let effect = target.call.call_effect().expect("an effect");
    for name in ["rsi", "rdi", "xmm6"] {
        assert!(effect.clobbers(register(&target, name)), "{name}");
    }
    assert!(effect.preserves(register(&target, "rbx")));
    let reads = effect.reads().call();
    assert!(reads.contains(&register(&target, "rdi")), "SysV's first");
    // `add rax, rsi` past the call reads an rsi the call may have written, never `a`.
    let text = rendered(&mut open, TWICE);
    assert!(!text.contains("+ (uint64_t)arg0"), "{text}");
    let mut unstated = pe(StatedConvention::Normal);
    let target = r2engine::native::Program::target_at(&unstated, TWICE).expect("a machine");
    let effect = target.call.call_effect().expect("an effect");
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
