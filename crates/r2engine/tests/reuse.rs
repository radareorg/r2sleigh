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

#[test]
fn a_listing_prepares_no_function_and_builds_no_binding_plan() {
    // The listing is the cheap request and has to stay cheap: every line is a
    // single instruction lifted on its own, and nothing about it needs a walk,
    // a prepare or a rendering.
    let mut program =
        OpenProgram::open(pinned().to_str().expect("the fixture path is text")).expect("it opens");
    program.ensure_assembled(FUNCTION).expect("it assembles");
    let memory = r2engine::query::Memory {
        program: &program,
        endian: program.endian(),
    };
    let answer = r2engine::query::listing(
        &program,
        &memory,
        r2engine::query::Listing {
            start: FUNCTION,
            count: 64,
        },
        r2engine::query::Work::InstructionLocal,
        program.revision(),
    );
    assert_eq!(answer.value.len(), 64);
    assert_eq!(
        program.memo_stats(),
        r2engine::query::MemoStats::default(),
        "a listing asked the engine to analyse a function"
    );
}

#[test]
fn a_patch_to_another_function_leaves_this_one_standing() {
    // The bytes moved, and nothing this analysis read did. Recording which
    // bytes were read is what tells those two apart; comparing revisions
    // alone made every write invalidate everything.
    let mut program =
        OpenProgram::open(pinned().to_str().expect("the fixture path is text")).expect("it opens");
    program.ensure_assembled(FUNCTION).expect("it assembles");
    {
        let target = program.target(FUNCTION).expect("the machine is described");
        program.analysed(&target, FUNCTION).expect("it prepares");
    }
    // `crc32_init` is another function entirely, and patching an instruction
    // in it renames nothing and moves no entry.
    program.image.write(0x401584, &[0x90]).expect("it patches");
    program.ensure_assembled(FUNCTION).expect("it reassembles");
    let target = program.target(FUNCTION).expect("the machine is described");
    program.analysed(&target, FUNCTION).expect("it prepares");
    let stats = program.memo_stats();
    assert_eq!(
        (stats.misses, stats.hits, stats.replacements),
        (1, 1, 0),
        "a patch to another function threw this analysis away"
    );
}
