//! One analysis serves every tier asked of one function.

mod common;

use common::{ONE, TWO, opened};

#[test]
fn every_tier_of_one_function_is_rendered_from_one_analysis() {
    let program = opened(ONE);
    let target = program.target(ONE).expect("the machine is described");
    for tier in [
        r2engine::RenderTier::C,
        r2engine::RenderTier::Structured,
        r2engine::RenderTier::Values,
    ] {
        let prepared = program.analysed(&target, ONE).expect("it prepares");
        let rendered = r2engine::native::rendered(&target, ONE, tier, &prepared, program.control());
        assert!(!rendered.output.clone().into_text().is_empty());
    }
    let stats = program.memo_stats();
    assert_eq!(
        (stats.misses, stats.hits, stats.replacements),
        (1, 2, 0),
        "three tiers walked and prepared the same body more than once"
    );
}

#[test]
fn a_patch_makes_the_held_analysis_stale() {
    let mut program = opened(ONE);
    {
        let target = program.target(ONE).expect("the machine is described");
        program.analysed(&target, ONE).expect("it prepares");
    }
    // `mov eax, 1` becomes `mov eax, 3`: a byte this analysis read.
    program.source_mut().write(ONE + 1, &[0x03]);
    program.ensure_assembled(ONE).expect("it reassembles");
    let target = program.target(ONE).expect("the machine is described");
    program.analysed(&target, ONE).expect("it prepares");
    assert_eq!(program.memo_stats().replacements, 1);
}

#[test]
fn a_patch_to_another_function_leaves_this_one_standing() {
    // The bytes moved, and nothing this analysis read did. Recording which
    // bytes were read is what tells those two apart; comparing revisions
    // alone made every write invalidate everything.
    let mut program = opened(ONE);
    {
        let target = program.target(ONE).expect("the machine is described");
        program.analysed(&target, ONE).expect("it prepares");
    }
    program.source_mut().write(TWO + 1, &[0x05]);
    program.ensure_assembled(ONE).expect("it reassembles");
    let target = program.target(ONE).expect("the machine is described");
    program.analysed(&target, ONE).expect("it prepares");
    let stats = program.memo_stats();
    assert_eq!(
        (stats.misses, stats.hits, stats.replacements),
        (1, 1, 0),
        "a patch to another function threw this analysis away"
    );
}

#[test]
fn a_listing_prepares_no_function_and_builds_no_binding_plan() {
    // The listing is the cheap request and has to stay cheap: every line is a
    // single instruction lifted on its own, and nothing about it needs a walk,
    // a prepare or a rendering.
    let program = opened(ONE);
    let answered = r2engine::query::Answered {
        decoders: &program,
        memory: r2engine::query::Memory {
            program: &program,
            endian: program.endian(),
        },
        facts: None,
    };
    let answer = r2engine::query::listing(
        &answered,
        r2engine::query::Listing {
            start: ONE,
            stop: r2engine::query::Stop::After(6),
        },
        r2engine::query::Work::BlockLocal,
        program.revision(),
    );
    assert_eq!(answer.value.len(), 6);
    assert_eq!(
        program.memo_stats(),
        r2engine::query::MemoStats::default(),
        "a listing asked the engine to analyse a function"
    );
}
