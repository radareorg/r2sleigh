//! The staged decompiler (ROADMAP D) through the open program: D1 writes the control, certified,
//! around D2's statements, with D3 spelling each term; a call is still a gap.

mod common;

use common::{CALLER, FORKED, ONE, opened};
use r2engine::RenderTier;

#[test]
fn the_staged_pipeline_renders_a_leaf_function_s_values() {
    let rendering = opened()
        .rendered(FORKED, RenderTier::Staged)
        .expect("the staged pipeline renders");
    let text = rendering.response.output.text().to_owned();
    // `test edi, edi; je L` is the test on the parameter; the merge is one variable both arms assign.
    assert!(
        text.contains("if ((uint8_t)((uint32_t)arg0 == (uint32_t)0U))"),
        "{text}"
    );
    assert!(text.contains("rax_3 = (uint64_t)0x1000U;"), "{text}");
    assert!(text.contains("rax_3 = (uint64_t)5U;"), "{text}");
    assert!(
        text.contains("return (uint64_t)((uint64_t)rax_3 + (uint64_t)8U);"),
        "{text}"
    );
    assert!(!text.contains("r2sleigh_residual"), "{text}");
    assert!(!text.contains("r2dec gap"), "{text}");
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
