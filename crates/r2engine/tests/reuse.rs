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
fn afi_afv_and_pdd_read_one_type_analysis() {
    // `afi`, then `afv`, then `pdd`: one prepared function, so one sealed type analysis.
    let mut program = opened();
    let first = program.function_info(ONE).expect("it is described");
    let second = program.function_info(ONE).expect("it is described again");
    assert_eq!(first, second);
    let rendering = program
        .rendered(ONE, r2engine::RenderTier::C)
        .expect("it renders");
    assert!(!rendering.response.output.into_text().is_empty());
    let stats = program.memo_stats();
    assert_eq!(
        (stats.misses, stats.hits, stats.sealed),
        (1, 2, 1),
        "each command ran its own type analysis of one prepared function"
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

/// `mov eax, [rip + 0xffa]; ret` at 0x1000: the value of the object at 0x2000.
const RETURNS_OBJECT: [u8; 7] = [0x8b, 0x05, 0xfa, 0x0f, 0x00, 0x00, 0xc3];

/// The amd64 machine a capture of an x86-64 function states.
fn amd64(embedded: &r2sleigh_lift::EmbeddedMachine) -> r2source::native::NativeMachine {
    let register = |name: &str| {
        let register = embedded
            .arch
            .registers
            .iter()
            .find(|register| register.name.eq_ignore_ascii_case(name))
            .expect("a named register");
        r2source::CanonicalStorageId {
            space: r2source::CanonicalStorageSpace::Register,
            offset: register.offset,
            size: register.size,
        }
    };
    let roles = r2source::SourceMachineRoles::new(Some(register("RIP")), Some(register("RSP")))
        .expect("machine roles")
        .with_role_register_names(r2source::SourceRoleRegisterNames::new(
            Some("RIP"),
            Some("RSP"),
            None,
        ));
    let slots = r2source::SourceConventionSlots::new(
        "amd64",
        ["RDI", "RSI", "RDX", "RCX", "R8", "R9"].map(register),
        Some(register("RAX")),
    )
    .expect("convention slots");
    r2source::native::NativeMachine {
        arch_id: "x86".to_owned(),
        cpu_id: embedded.cpu.to_owned(),
        bits: 64,
        endianness: r2source::SourceEndianness::Little,
        roles,
        slots,
        call_effect: None,
    }
}

/// The C for that function in a program whose object at 0x2000 has this declared type.
fn rendered_returning_object(declared: Option<&str>) -> String {
    use r2source::native::{NativeBlock, NativeFunction};
    let embedded = r2sleigh_lift::embedded_machine("x86-64").expect("an x86-64 machine");
    let machine = amd64(&embedded);
    let function = NativeFunction {
        address: 0x1000,
        name: "sym.object".to_owned(),
        blocks: vec![NativeBlock {
            address: 0x1000,
            bytes: RETURNS_OBJECT.to_vec(),
            successors: Vec::new(),
            switch: None,
        }],
        calls: Vec::new(),
        string_literals: Vec::new(),
        data_symbols: vec![r2source::SourceDataObject::new(
            0x2000,
            "obj.counter",
            declared,
        )],
        code_pointer_tables: Vec::new(),
        interface: None,
        parameter_names: Vec::new(),
        stack_slot_names: Vec::new(),
        signature: None,
        loader_role: None,
    };
    let snapshot = r2source::native::capture(&machine, function).expect("a capture");
    let lifted = r2sleigh_lift::Disassembler::lift_owned_function(snapshot).expect("a lift");
    let artifact = r2ssa::TrustedSsaArtifact::prepare(lifted).expect("a prepared body");
    let input = r2engine::EngineFunctionDecompileRequestInput::single_function(
        r2engine::EngineFunctionInput {
            function_name: "sym.object".to_owned(),
            function_addr: 0x1000,
            blocks: Vec::new(),
            arch: Some(embedded.arch),
            semantic_metadata_enabled: true,
            source_snapshot: None,
        },
        Some(64),
        r2types::ParsedExternalContext {
            program_extents: r2types::ProgramExtents::new([(0x1000, 0x1007), (0x2000, 0x2004)]),
            ..r2types::ParsedExternalContext::default()
        },
    )
    .with_input_quality(r2engine::EngineFunctionInputQuality::complete(1))
    .with_trusted_ssa(std::sync::Arc::new(artifact));
    r2engine::EngineSession::new()
        .decompile_function_from_input(input)
        .output
        .into_text()
}

#[test]
fn a_data_object_type_stays_with_the_program_that_stated_it() {
    let fresh = rendered_returning_object(None);
    let typed = rendered_returning_object(Some("int32_t"));
    assert!(typed.contains("int32_t counter"), "{typed}");
    assert_eq!(
        rendered_returning_object(None),
        fresh,
        "a type another program stated reached this one"
    );
}
