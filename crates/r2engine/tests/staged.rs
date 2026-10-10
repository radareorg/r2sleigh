//! The staged decompiler (ROADMAP D) through the open program: D1 writes the control, certified,
//! around D2's statements, with D3 spelling each term; a call is still a gap.

mod common;

use common::{BASE, CALLER, FORKED, GLIBC, Literal, ONE, PLT_STUB, STUB, TWO, opened};
use r2engine::RenderTier;
use r2engine::program::OpenProgram;

#[test]
fn the_staged_pipeline_renders_a_leaf_function_s_values() {
    let rendering = opened()
        .rendered(FORKED, RenderTier::Staged)
        .expect("the staged pipeline renders");
    let text = rendering.response.output.text().to_owned();
    // `test edi, edi; je L` is the test on the parameter; the merge is one variable both arms
    // assign, so it is one assignment of the value the test selects.
    assert!(
        text.contains("rax_3 = (uint8_t)((uint32_t)arg0 == (uint32_t)0U) ? 0x1000 : 5;"),
        "{text}"
    );
    assert!(
        text.contains("return (uint64_t)((uint64_t)rax_3 + (uint64_t)8U);"),
        "{text}"
    );
    assert!(!text.contains("r2sleigh_residual"), "{text}");
    assert!(!text.contains("r2dec gap"), "{text}");
    // The proof line every rendering opens with, from the obligation ledger the staged pipeline closes.
    assert!(
        text.contains("/* r2dec proof: no individual construct is marked;")
            && text.contains("13 source obligations: 10 rendered, 3 elided, 0 refused;"),
        "{text}"
    );
    let closure = rendering
        .response
        .obligation_ledger
        .expect("a ledger")
        .close();
    assert!(closure.total > 0, "{text}");
    assert_eq!(closure.gapped, 0, "every obligation is rendered: {text}");
    // Each written line names the instructions it stands for, all of them `forked`'s.
    let r2engine::EngineRendering::Function(rendered) = &rendering.response.output else {
        panic!("nothing rendered: {text}");
    };
    let lines = rendered.emission().lines();
    assert!(!lines.is_empty(), "{text}");
    for line in lines {
        assert!(
            line.addrs
                .iter()
                .all(|addr| (FORKED..FORKED + 0x15).contains(addr)),
            "{line:?}\n{text}"
        );
    }
}

#[test]
fn a_described_call_is_written_from_the_callsite_facts() {
    let rendering = opened()
        .rendered(CALLER, RenderTier::Staged)
        .expect("the staged pipeline renders");
    let text = rendering.response.output.text().to_owned();
    // `call one; ret`: the result register the call leaves is what `caller` returns.
    assert!(text.contains("uint64_t one(void);"), "{text}");
    assert!(text.contains("rax_1 = one();"), "{text}");
    assert!(text.contains("return (uint64_t)rax_1;"), "{text}");
    // `one` returns, so nothing may tell C otherwise; its return push writes nothing.
    assert!(!text.contains("noreturn"), "{text}");
    assert!(!text.contains("r2sleigh_store"), "{text}");
    assert!(!text.contains("r2dec gap"), "{text}");
    let r2engine::EngineRendering::Function(rendered) = &rendering.response.output else {
        panic!("nothing rendered: {text}");
    };
    let links = rendered.emission().links();
    assert!(
        links
            .iter()
            .any(|link| link.ident == "one" && link.addr == Some(ONE)),
        "{links:?}"
    );
}

/// `mov edi, 1; call exit; mov eax, 7; ret`: the walk gives the call's block no successor, as the
/// library's declaration of `exit` says, so the call is declared `noreturn` and ends the text there.
#[test]
fn a_call_the_block_graph_never_returns_from_is_declared_noreturn() {
    let mut program = OpenProgram::of(Literal::new().importing("exit").running_on(GLIBC));
    let call = i32::try_from(STUB as i64 - (TWO + 10) as i64).expect("near");
    let mut code = vec![0xbf, 0x01, 0, 0, 0, 0xe8];
    code.extend_from_slice(&call.to_le_bytes());
    code.extend_from_slice(&[0xb8, 0x07, 0, 0, 0, 0xc3]);
    program.source_mut().write(TWO, &code);
    let rendering = program
        .rendered(TWO, RenderTier::Staged)
        .expect("the staged pipeline renders");
    let text = rendering.response.output.text().to_owned();
    assert!(
        text.contains("__attribute__((noreturn)) void exit(int32_t);"),
        "{text}"
    );
    // `1` is an `int` the declaration holds, so it is passed as the number.
    assert!(text.contains("exit(1);"), "{text}");
    // Nothing follows the call: no trap stands for the edge the block does not have, and no return.
    assert!(!text.contains("r2sleigh_residual"), "{text}");
    assert!(
        !text
            .lines()
            .any(|line| line.trim_start().starts_with("return")),
        "{text}"
    );
}

/// `L: test rdi, rdi; je D; mov rdx, rax; mov rax, rcx; mov rcx, rdx; sub rdi, 1; jmp L;
/// D: sub rax, rcx; ret`: the merges swap on the back edge, each copy reading what the other writes.
#[test]
fn merges_that_swap_copy_through_a_temporary() {
    const SWAPS: &[u8] = &[
        0x48, 0x89, 0xf0, 0x48, 0x89, 0xd1, 0x48, 0x85, 0xff, 0x74, 0x0f, 0x48, 0x89, 0xc2, 0x48,
        0x89, 0xc8, 0x48, 0x89, 0xd1, 0x48, 0x83, 0xef, 0x01, 0xeb, 0xec, 0x48, 0x29, 0xc8, 0xc3,
    ];
    let program = Literal::of_code(SWAPS, &[("swaps", BASE, SWAPS.len() as u64)]).running_on(GLIBC);
    let rendering = OpenProgram::of(program)
        .rendered(BASE, RenderTier::Staged)
        .expect("the staged pipeline renders");
    let text = rendering.response.output.text().to_owned();
    assert!(text.contains("_next = "), "{text}");
    assert!(!text.contains("r2dec gap"), "{text}");
}

/// A stub is one jump through the slot the loader fills with `_Exit`. r2engine's route decides it
/// once, and both pipelines render the import's declaration, never a body forwarding through it.
#[test]
fn an_import_stub_is_its_import_s_declaration_in_both_pipelines() {
    let mut program = OpenProgram::of(Literal::plt());
    for tier in [RenderTier::C, RenderTier::Staged] {
        let text = program
            .rendered(PLT_STUB, tier)
            .expect("it renders")
            .response
            .output
            .into_text();
        assert!(
            text.contains(&format!("import stub at {PLT_STUB:#x}")) && text.contains("`_Exit`"),
            "{tier:?}: {text}"
        );
        assert!(!text.contains("return"), "{tier:?}: {text}");
        assert!(!text.contains("r2sleigh_residual"), "{tier:?}: {text}");
    }
}
