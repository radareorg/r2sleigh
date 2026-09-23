//! One analysis serves every tier asked of one function.

mod common;

use common::{ARM_ENTRY, Literal, ONE, STUB, TEXT, THUMB_CALLED, THUMB_LEAF, TWO, opened};
use r2engine::program::OpenProgram;

#[test]
fn every_tier_of_one_function_is_rendered_from_one_analysis() {
    let mut program = opened();
    for tier in [
        r2engine::RenderTier::C,
        r2engine::RenderTier::Structured,
        r2engine::RenderTier::Values,
    ] {
        let rendering = program.rendered(ONE, tier).expect("it renders");
        assert!(!rendering.response.output.into_text().is_empty());
    }
    let stats = program.memo_stats();
    assert_eq!(
        (stats.misses, stats.hits, stats.replacements),
        (1, 2, 0),
        "three tiers walked and prepared the same body more than once"
    );
}

#[test]
fn deriving_the_tables_the_first_time_is_not_a_change() {
    let mut program = opened();
    program.prepared(ONE).expect("it prepares");
    let revision = program.revision();
    assert_eq!((revision.names, revision.entries), (0, 0));
}

#[test]
fn a_patch_makes_the_held_analysis_stale() {
    let mut program = opened();
    program.prepared(ONE).expect("it prepares");
    // `mov eax, 1` becomes `mov eax, 3`: a byte this analysis read.
    program.source_mut().write(ONE + 1, &[0x03]);
    program.prepared(ONE).expect("it prepares");
    assert_eq!(program.memo_stats().replacements, 1);
}

#[test]
fn a_patch_after_a_hit_still_makes_the_held_analysis_stale() {
    // A hit reads nothing, and recording that empty read set over the one the
    // derivation made left the analysis standing against every later write.
    let mut program = opened();
    program.prepared(ONE).expect("it prepares");
    program.prepared(ONE).expect("it is served");
    program.source_mut().write(ONE + 1, &[0x03]);
    program.prepared(ONE).expect("it prepares");
    let stats = program.memo_stats();
    assert_eq!(
        (stats.misses, stats.hits, stats.replacements),
        (2, 1, 1),
        "a write to bytes this analysis read was served the old analysis"
    );
}

#[test]
fn a_patch_to_another_function_leaves_this_one_standing() {
    // The bytes moved, and nothing this analysis read did. Recording which
    // bytes were read is what tells those two apart; comparing revisions
    // alone made every write invalidate everything.
    let mut program = opened();
    program.prepared(ONE).expect("it prepares");
    program.source_mut().write(TWO + 1, &[0x05]);
    program.prepared(ONE).expect("it prepares");
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
    let mut program = opened();
    let answer = program
        .listing(r2engine::query::Listing {
            start: ONE,
            stop: r2engine::query::Stop::After(6),
        })
        .expect("it lists");
    assert_eq!(answer.value.len(), 6);
    assert_eq!(
        program.memo_stats(),
        r2engine::query::MemoStats::default(),
        "a listing asked the engine to analyse a function"
    );
}

#[test]
fn a_patch_that_names_a_string_makes_every_held_analysis_stale() {
    // The walk asks the name table about addresses it never reads, so a new
    // name anywhere is a new program to it even though no byte it read moved.
    let mut program = OpenProgram::of(Literal::new().with_data());
    program.prepared(ONE).expect("it prepares");
    let before = program.revision();
    program.source_mut().write(TEXT, b"hello\0");
    program.prepared(ONE).expect("it prepares");
    assert_eq!(program.names().text_at(TEXT), Some("hello"));
    let after = program.revision();
    assert_eq!(
        (after.names, after.entries),
        (before.names + 1, before.entries)
    );
    assert_eq!(program.memo_stats().replacements, 1);
}

#[test]
fn a_patch_that_moves_an_import_stub_makes_every_held_analysis_stale() {
    // The stub table decides which addresses are entries, which bounds every
    // walk, so a patch that unmakes a stub is a new program to every body.
    let mut program = OpenProgram::of(Literal::new().importing("puts"));
    program.prepared(ONE).expect("it prepares");
    assert_eq!(
        program.imports().get(&STUB).map(String::as_str),
        Some("puts")
    );
    let before = program.revision().entries;
    // `jmp [rip + 2]` becomes `jmp [rip + 0x10]`, which reads no slot.
    program.source_mut().write(STUB + 2, &[0x10]);
    program.prepared(ONE).expect("it prepares");
    assert!(program.imports().is_empty());
    assert_eq!(program.revision().entries, before + 1);
    let stats = program.memo_stats();
    assert_eq!((stats.misses, stats.hits, stats.replacements), (2, 0, 1));
}

#[test]
fn a_patch_that_changes_a_callee_s_instruction_set_makes_its_analysis_stale() {
    // `blx` becomes `bl`, so the callee is entered in ARM; the leaf's own
    // bytes are untouched, but the instruction set it is read in moved.
    let mut program = OpenProgram::of(Literal::arm_thumb());
    program.prepared(THUMB_LEAF).expect("it prepares");
    let before = program.revision().entries;
    // Discovering the instruction sets the first time is no change.
    assert_eq!(before, 0);
    program.source_mut().write(ARM_ENTRY + 3, &[0xeb]);
    let _ = program.prepared(THUMB_LEAF);
    assert_eq!(program.revision().entries, before + 1);
    assert_eq!(program.memo_stats().replacements, 1);
    let called = program
        .functions()
        .expect("discovery runs")
        .iter()
        .find(|one| one.address == THUMB_CALLED)
        .map(|one| one.thumb);
    assert_eq!(called, Some(false));
    // A write that moves no function's instruction set moves nothing.
    program.source_mut().write(ARM_ENTRY + 3, &[0xeb]);
    program.functions().expect("discovery runs");
    assert_eq!(program.revision().entries, before + 1);
}
