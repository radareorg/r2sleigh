//! A function's convention is its language's (ROADMAP LP1): Go's register ABI, or a refusal.

use crate::common;

use common::{BASE, GLIBC, Literal};
use r2engine::native::NativeRefusal;
use r2engine::program::OpenProgram;

/// `lea rax, [rax + rbx]; ret`: Go's ABIInternal passes its first two integers in RAX and RBX.
const ADDS: &[u8] = &[0x48, 0x8d, 0x04, 0x18, 0xc3];

/// The C, or the refusal record's reason where the analysis refused (ROADMAP D29).
fn rendered(program: Literal) -> Result<String, String> {
    let rendering = OpenProgram::of(program.running_on(GLIBC))
        .rendered(BASE)
        .expect("a refusal is a record, never an error");
    match rendering.refused {
        Some(refusal) => {
            assert!(
                matches!(refusal, NativeRefusal::Convention { .. }),
                "{refusal:?}"
            );
            let text = rendering.response.output.into_text();
            assert!(text.contains(&refusal.to_string()), "{text}");
            Err(refusal.to_string())
        }
        None => Ok(rendering.response.output.into_text()),
    }
}

#[test]
fn a_go_function_takes_its_arguments_where_go_passes_them() {
    let adds = || Literal::of_code(ADDS, &[("main.adds", BASE, 5)]);
    let go = rendered(adds().in_go(Some((1, 18)), Some(&[]))).expect("Go 1.18 renders");
    // RAX and RBX are Go's first two integer slots: two parameters, both summed into the result.
    let parameters = common::parameters(&go);
    assert_eq!(parameters.len(), 2, "{go}");
    let returned = go
        .lines()
        .find(|line| line.trim_start().starts_with("return"))
        .unwrap_or_else(|| panic!("no return: {go}"));
    for (_, name) in &parameters {
        assert!(
            returned.contains(name.as_str()),
            "{name} is not summed: {go}"
        );
    }
    assert!(!go.contains("residual"), "{go}");
    // The same bytes as C: RAX and RBX are no System V argument, so they are read from entry.
    let c = rendered(adds()).expect("C renders");
    assert!(common::parameters(&c).is_empty(), "{c}");
    assert!(c.contains("residual"), "{c}");
}

#[test]
fn a_go_function_under_the_stack_abi_refuses_with_that_reason() {
    let adds = Literal::of_code(ADDS, &[("main.adds", BASE, 5)]).in_go(Some((1, 14)), None);
    let refused = rendered(adds).expect_err("ABI0 results are on the stack");
    assert!(refused.contains("golang_abi0"), "{refused}");
}

/// Go 1.17 on: compiled functions run ABIInternal, an assembly one keeps ABI0 behind its wrapper.
#[test]
fn an_assembly_go_function_keeps_abi0_and_an_unstated_one_refuses() {
    let adds = || Literal::of_code(ADDS, &[("main.adds", BASE, 5)]);
    let assembly = rendered(adds().in_go(Some((1, 18)), Some(&[BASE])))
        .expect_err("ABI0 results are on the stack");
    assert!(assembly.contains("golang_abi0"), "{assembly}");
    // Go 1.17's pclntab marks no function as assembly, so no function's ABI is stated.
    let unstated = rendered(adds().in_go(Some((1, 17)), None)).expect_err("no ABI is stated");
    assert!(unstated.contains("states no function's ABI"), "{unstated}");
}

/// Go's prologue, a body ending in `call runtime.throw`, and the growth block after that call:
/// `lea r12, [rsp-0x20]; cmp r12, [r14+0x10]; jbe grow; sub rsp, 0x28; call throw;
/// grow: call morestack_noctxt; jmp entry`.
const THROWS: &[u8] = &[
    0x4c, 0x8d, 0x64, 0x24, 0xe0, // 0x00 lea r12, [rsp - 0x20]
    0x4d, 0x3b, 0x66, 0x10, // 0x05 cmp r12, [r14 + 0x10]
    0x76, 0x09, // 0x09 jbe 0x14
    0x48, 0x83, 0xec, 0x28, // 0x0b sub rsp, 0x28
    0xe8, 0x2c, 0x00, 0x00, 0x00, // 0x0f call 0x40
    0xe8, 0x17, 0x00, 0x00, 0x00, // 0x14 call 0x30
    0xe9, 0xe2, 0xff, 0xff, 0xff, // 0x19 jmp 0x00
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, // 0x1e
    0xc3, // 0x30 runtime.morestack_noctxt
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xc3, // 0x40 runtime.throw
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

/// Go's compiler ends a block after `runtime.throw`, so under the runtime's contract the call
/// never returns: the check is decided and the premise is stated where the body ends and where
/// `afi` says it never returns. As C, `throw` returns, so nothing says either never returns.
#[test]
fn a_go_runtime_panic_ends_its_caller_under_the_runtime_s_contract() {
    let throws = || {
        Literal::of_code(
            THROWS,
            &[
                ("main.f", BASE, 0x1e),
                ("runtime.morestack_noctxt", BASE + 0x30, 1),
                ("runtime.throw", BASE + 0x40, 1),
            ],
        )
    };
    let go = rendered(throws().in_go(Some((1, 21)), Some(&[]))).expect("Go renders");
    assert!(!go.contains("morestack"), "{go}");
    assert!(
        go.contains("1 call never returns (assuming go-runtime)"),
        "{go}"
    );
    assert!(
        go.contains("compiler-inserted (assuming go-runtime)"),
        "{go}"
    );
    let mut program = OpenProgram::of(throws().in_go(Some((1, 21)), Some(&[])).running_on(GLIBC));
    // `runtime.throw` is the model's word; `main.f` composes it (D380).
    let assumed = |proof| {
        Some(r2engine::discovery::Never {
            proof,
            premises: std::collections::BTreeSet::from([r2engine::discovery::Premise::GoRuntime]),
        })
    };
    for (entry, proof) in [
        (BASE, r2engine::discovery::NeverProof::Composed),
        (BASE + 0x40, r2engine::discovery::NeverProof::Declared),
    ] {
        let info = program.function_info(entry).expect("described");
        assert_eq!(info.noreturn, assumed(proof), "{entry:#x}");
    }
    let c = rendered(throws()).expect("C renders");
    assert!(!c.contains("never return"), "{c}");
    // As C, `main.f` loops back to its entry and no walk reaches a return: a bound, never a proof (D380).
    let mut c = OpenProgram::of(throws().running_on(GLIBC));
    let noreturn =
        |c: &mut OpenProgram<Literal>, entry| c.function_info(entry).expect("described").noreturn;
    assert_eq!(
        noreturn(&mut c, BASE),
        Some(r2engine::discovery::Never {
            proof: r2engine::discovery::NeverProof::NoReturnReached,
            premises: std::collections::BTreeSet::new(),
        })
    );
    assert_eq!(noreturn(&mut c, BASE + 0x40), None);
}

/// A refused convention leaves what the walk shows: `afi`'s blocks stand, and the parameters,
/// locals, convention and calls it would decide are unknown, not empty (ROADMAP D29).
#[test]
fn a_refused_convention_keeps_the_walks_facts() {
    let adds = Literal::of_code(ADDS, &[("main.adds", BASE, 5)]).in_go(Some((1, 14)), None);
    let mut program = OpenProgram::of(adds.running_on(GLIBC));
    let info = program.function_info(BASE).expect("a refusal is a record");
    let refused = info
        .refused
        .as_ref()
        .expect("ABI0 results are on the stack");
    assert_eq!(refused.kind(), "convention", "{refused}");
    assert_eq!((info.blocks.len(), info.instructions()), (1, 2));
    assert_eq!((info.min_addr(), info.max_addr()), (BASE, BASE + 5));
    assert!(info.convention.is_none() && info.arguments.is_empty() && info.locals.is_empty());
    assert!(info.returns.is_none() && info.calls.is_empty());
}
