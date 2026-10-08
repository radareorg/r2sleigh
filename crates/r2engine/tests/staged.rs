//! The staged decompiler (ROADMAP D) through the open program: D1 writes the control, certified,
//! around D2's statements, with D3 spelling each term; a call is still a gap.

mod common;

use common::{CALLER, FORKED, opened};
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
}

#[test]
fn a_call_is_a_gap_and_its_obligations_are_gapped() {
    let rendering = opened()
        .rendered(CALLER, RenderTier::Staged)
        .expect("the staged pipeline renders");
    let text = rendering.response.output.text().to_owned();
    assert!(text.contains("r2dec gap: CallNotRendered"), "{text}");
    // The push of the return address is the call's own transfer: no store into the frame.
    assert!(!text.contains("r2sleigh_store"), "{text}");
    let closure = rendering
        .response
        .obligation_ledger
        .expect("a ledger")
        .close();
    assert!(closure.gapped > 0, "the call is not rendered: {text}");
}
