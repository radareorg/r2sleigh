//! A function's convention is its language's (ROADMAP LP1): Go's register ABI, or a refusal.

mod common;

use common::{BASE, GLIBC, Literal};
use r2engine::RenderTier;
use r2engine::program::OpenProgram;

/// `lea rax, [rax + rbx]; ret`: Go's ABIInternal passes its first two integers in RAX and RBX.
const ADDS: &[u8] = &[0x48, 0x8d, 0x04, 0x18, 0xc3];

fn rendered(program: Literal) -> Result<String, String> {
    OpenProgram::of(program.running_on(GLIBC))
        .rendered(BASE, RenderTier::C)
        .map(|rendering| rendering.response.output.into_text())
}

#[test]
fn a_go_function_takes_its_arguments_where_go_passes_them() {
    let adds = || Literal::of_code(ADDS, &[("main.adds", BASE, 5)]);
    let go = rendered(adds().in_go(Some((1, 18)), Some(&[]))).expect("Go 1.18 renders");
    let signature = go.lines().next().unwrap_or_default();
    assert!(
        signature.contains("RAX_0") && signature.contains("RBX_0"),
        "{go}"
    );
    assert!(!go.contains("residual"), "{go}");
    // The same bytes as C: RAX and RBX are no System V argument, so they are read from entry.
    let c = rendered(adds()).expect("C renders");
    assert!(
        !c.lines().next().unwrap_or_default().contains("RBX_0"),
        "{c}"
    );
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
