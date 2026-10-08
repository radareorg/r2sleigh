//! The staged decompiler (ROADMAP D) through the open program: D1 writes the control, certified,
//! with every block's operations one gap and every obligation counted as gapped.

mod common;

use common::{FORKED, opened};
use r2engine::RenderTier;

#[test]
fn the_staged_pipeline_places_every_block_once_and_gaps_its_values() {
    let rendering = opened()
        .rendered(FORKED, RenderTier::Staged)
        .expect("the staged pipeline renders");
    let text = rendering.response.output.text().to_owned();
    // `forked` branches once: one `if` on a residual test, each arm a gap.
    assert_eq!(
        text.matches("if (r2sleigh_residual_bool(").count(),
        1,
        "{text}"
    );
    assert!(text.contains("r2dec gap: ValuesNotRendered"), "{text}");
    let ledger = rendering.response.obligation_ledger.expect("a ledger");
    let closure = ledger.close();
    assert!(closure.total > 0, "{text}");
    assert_eq!(
        closure.gapped, closure.total,
        "every obligation is gapped until D2"
    );
}
