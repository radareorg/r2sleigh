//! One analysis serves every tier asked of one function.

use std::path::PathBuf;

use r2engine::program::OpenProgram;

/// A GCC-built x86-64 ELF the repository ships as bytes.
fn pinned() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/coverage/pinned/hashes_gcc_x64_O2")
}

/// A small hash loop in that binary.
const FUNCTION: u64 = 0x401330;

#[test]
fn every_tier_of_one_function_is_rendered_from_one_analysis() {
    let mut program =
        OpenProgram::open(pinned().to_str().expect("the fixture path is text")).expect("it opens");
    program.ensure_assembled(FUNCTION).expect("it assembles");
    let target = program.target(FUNCTION).expect("the machine is described");

    for tier in [
        r2engine::RenderTier::C,
        r2engine::RenderTier::Structured,
        r2engine::RenderTier::Values,
    ] {
        let prepared = program.analysed(&target, FUNCTION).expect("it prepares");
        let rendered =
            r2engine::native::rendered(&target, FUNCTION, tier, &prepared, program.control());
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
    let mut program =
        OpenProgram::open(pinned().to_str().expect("the fixture path is text")).expect("it opens");
    program.ensure_assembled(FUNCTION).expect("it assembles");
    {
        let target = program.target(FUNCTION).expect("the machine is described");
        program.analysed(&target, FUNCTION).expect("it prepares");
    }
    // Writing anywhere in the program moves its byte revision, and the held
    // analysis was of the program as it was.
    program.image.write(FUNCTION, &[0x90]).expect("it patches");
    program.ensure_assembled(FUNCTION).expect("it reassembles");
    let target = program.target(FUNCTION).expect("the machine is described");
    let _ = program.analysed(&target, FUNCTION);
    assert_eq!(program.memo_stats().replacements, 1);
}
