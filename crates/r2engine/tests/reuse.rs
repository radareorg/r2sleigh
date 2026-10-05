//! One analysis serves every tier asked of one function.

mod common;

use common::{
    ARM_ENTRY, CALLER, Literal, ONE, PASSES, STUB, TEXT, THUMB_CALLED, THUMB_LEAF, TWO, opened,
};
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
    let stats = program.analysis_stats();
    assert_eq!(
        (
            stats.analysed.computed,
            stats.analysed.reused,
            stats.analysed.recomputed
        ),
        // Two tiers and the one sealing reuse the analysis the first tier computed.
        (1, 3, 0),
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
    let stats = program.analysis_stats();
    assert_eq!(
        (
            stats.analysed.computed,
            stats.analysed.reused,
            stats.sealed.computed
        ),
        // Two commands and the one sealing reuse the analysis the first computed.
        (1, 3, 1),
        "each command ran its own type analysis of one prepared function"
    );
}

#[test]
fn a_patch_makes_the_held_analysis_stale() {
    let mut program = opened();
    program.prepared(ONE).expect("it prepares");
    // `mov eax, 1` becomes `mov eax, 3`: a byte this analysis read.
    program.source_mut().write(ONE + 1, &[0x03]);
    program.prepared(ONE).expect("it prepares");
    assert_eq!(program.analysis_stats().analysed.recomputed, 1);
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
    let stats = program.analysis_stats();
    assert_eq!(
        (
            stats.analysed.computed,
            stats.analysed.reused,
            stats.analysed.recomputed
        ),
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
    let stats = program.analysis_stats();
    assert_eq!(
        (
            stats.analysed.computed,
            stats.analysed.reused,
            stats.analysed.recomputed
        ),
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
        program.analysis_stats(),
        r2engine::query::AnalysisStats::default(),
        "a listing asked the engine to analyse a function"
    );
}

#[test]
fn a_patch_that_names_a_string_makes_every_held_analysis_stale() {
    // The walk asks the name table about addresses it never reads, so a new
    // name anywhere is a new program to it even though no byte it read moved.
    let mut program = OpenProgram::of(Literal::new().with_data());
    program.prepared(ONE).expect("it prepares");
    program.source_mut().write(TEXT, b"hello\0");
    program.prepared(ONE).expect("it prepares");
    assert_eq!(program.names().text_at(TEXT), Some("hello"));
    assert_eq!(program.analysis_stats().analysed.recomputed, 1);
}

#[test]
fn a_patch_that_moves_an_import_stub_makes_every_held_analysis_stale() {
    // The stub table decides which addresses are entries, which bounds every
    // walk, so a patch that unmakes a stub is a new program to every body.
    let mut program = OpenProgram::of(Literal::new().importing("puts"));
    program.prepared(ONE).expect("it prepares");
    assert_eq!(
        program
            .imports()
            .get(&STUB)
            .map(|stub| stub.symbol.as_str()),
        Some("puts")
    );
    // `jmp [rip + 2]` becomes `jmp [rip + 0x10]`, which reads no slot.
    program.source_mut().write(STUB + 2, &[0x10]);
    program.prepared(ONE).expect("it prepares");
    assert!(program.imports().is_empty());
    let stats = program.analysis_stats();
    assert_eq!(
        (
            stats.analysed.computed,
            stats.analysed.reused,
            stats.analysed.recomputed
        ),
        (2, 0, 1)
    );
}

#[test]
fn a_patch_that_changes_a_callee_s_instruction_set_makes_its_analysis_stale() {
    // `blx` becomes `bl`, so the callee is entered in ARM; the leaf's own
    // bytes are untouched, but the instruction set it is read in moved.
    let mut program = OpenProgram::of(Literal::arm_thumb());
    program.prepared(THUMB_LEAF).expect("it prepares");
    program.source_mut().write(ARM_ENTRY + 3, &[0xeb]);
    let _ = program.prepared(THUMB_LEAF);
    // The leaf is read in another instruction set, a new key: the old analysis is never served.
    assert_eq!(program.analysis_stats().analysed.computed, 2);
    let called = program
        .functions()
        .expect("discovery runs")
        .iter()
        .find(|one| one.address == THUMB_CALLED)
        .map(|one| one.thumb);
    assert_eq!(called, Some(false));
    // A write that moves no function's instruction set leaves the leaf's analysis standing.
    program.source_mut().write(ARM_ENTRY + 3, &[0xeb]);
    let _ = program.prepared(THUMB_LEAF);
    assert_eq!(program.analysis_stats().analysed.computed, 2);
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
            unresolved: false,
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
        frame_saves: Vec::new(),
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

#[test]
fn a_patch_that_stops_a_callee_s_callee_returning_makes_the_caller_stale() {
    // `caller` calls `two`, which calls `one`; the caller's analysis reads `two` and asks only whether `one` returns.
    let mut program = opened();
    program
        .source_mut()
        .write(TWO, &[0xe8, 0xdb, 0xff, 0xff, 0xff, 0xc3]);
    program
        .source_mut()
        .write(CALLER, &[0xe8, 0x0b, 0x00, 0x00, 0x00, 0xc3]);
    let ends = |program: &mut OpenProgram<Literal>| {
        let prepared = program.prepared(CALLER).expect("it prepares");
        let blocks = prepared.lifted();
        blocks
            .iter()
            .map(|block| block.addr + u64::from(block.size))
            .max()
    };
    assert_eq!(ends(&mut program), Some(CALLER + 6));
    // `one` becomes `jmp one`, a byte the caller's analysis never read.
    program.source_mut().write(ONE, &[0xeb, 0xfe]);
    assert_eq!(ends(&mut program), Some(CALLER + 5));
    let stats = program.analysis_stats();
    assert_eq!(
        (
            stats.analysed.computed,
            stats.analysed.reused,
            stats.analysed.recomputed
        ),
        (2, 0, 1)
    );
}

#[test]
fn two_callers_of_one_callee_prepare_it_once_and_both_see_a_write_to_it() {
    // `caller` and `passes` both call `one`. The callee is prepared against
    // the program alone, so the second root reads what the first derived --
    // and with it the bytes that derivation read, or a write to the callee
    // would leave the second root's analysis standing on the old callee.
    let mut program = opened();
    program.prepared(CALLER).expect("it prepares");
    program.prepared(PASSES).expect("it prepares");
    let stats = program.analysis_stats();
    assert_eq!(
        (stats.callee_reads.computed, stats.callee_reads.reused),
        (1, 1),
        "the second caller prepared the shared callee again"
    );
    // `mov eax, 1` becomes `mov eax, 3` in the callee alone.
    program.source_mut().write(ONE + 1, &[0x03]);
    program.prepared(PASSES).expect("it prepares");
    let stats = program.analysis_stats();
    assert_eq!(
        (stats.analysed.recomputed, stats.callee_reads.computed),
        (1, 2),
        "a root that read a held callee did not see a write to that callee"
    );
}

#[test]
fn a_listing_asks_a_held_callee_what_its_parameters_take_without_preparing_it() {
    // `hands` hands `ident` a number that does not move with the program.
    // Whether it is an address is what `ident`'s body does with the
    // parameter, which preparing `hands` already read.
    let mut code = common::HANDING.to_vec();
    code[0x10..0x1b].copy_from_slice(&[
        0xbf, 0x40, 0x10, 0x00, 0x00, // mov edi, 0x1040
        0xe8, 0xe6, 0xff, 0xff, 0xff, // call ident
        0xc3, // ret
    ]);
    let functions = [("ident", common::BASE, 4), ("hands", common::HANDS, 0xb)];
    let mut program =
        OpenProgram::of(Literal::of_code(code.leak(), &functions).with_data_after(common::HANDED));
    program.prepared(common::HANDS).expect("it prepares");
    let before = program.analysis_stats();
    assert_eq!(
        (before.callee_reads.computed, before.callee_reads.reused),
        (1, 0)
    );
    program.function_listing(common::HANDS).expect("it lists");
    let after = program.analysis_stats();
    assert_eq!(
        (after.callee_reads.computed, after.callee_reads.reused),
        (1, 1),
        "the listing prepared a callee whose summary was held"
    );
}

#[test]
fn a_rendering_is_redrawn_without_analysing_again() {
    // `pdd` on one function, another, then the first: the session redraws what it rendered.
    let mut program = opened();
    let text = |program: &mut OpenProgram<Literal>, entry| {
        let rendering = program.rendered(entry, r2engine::RenderTier::C);
        rendering.expect("it renders").response.output.into_text()
    };
    let first = text(&mut program, ONE);
    text(&mut program, TWO);
    assert_eq!(text(&mut program, ONE), first);
    let stats = program.analysis_stats();
    assert_eq!(
        (stats.rendered.computed, stats.rendered.reused),
        (2, 1),
        "the first function was rendered again"
    );
    // `mov eax, 1` becomes `mov eax, 3`: the rendering read it.
    program.source_mut().write(ONE + 1, &[0x03]);
    assert_ne!(text(&mut program, ONE), first);
}

#[test]
fn a_rendering_the_request_stopped_is_not_held() {
    let mut program = opened();
    let cancellation = r2engine::EngineCancellationToken::default();
    program.begin_request(r2engine::EngineExecutionControl::with_cancellation(
        cancellation.clone(),
    ));
    cancellation.cancel();
    let _ = program.rendered(ONE, r2engine::RenderTier::C);
    let rendering = program
        .rendered(ONE, r2engine::RenderTier::C)
        .expect("a fresh request renders");
    assert!(!rendering.response.output.into_text().is_empty());
    assert_eq!(
        program.analysis_stats().analysed.computed,
        2,
        "the stopped analysis was served"
    );
}

/// One question the property test asks of a program and of a fresh open of its bytes.
#[derive(Debug, Clone)]
enum Step {
    Write(u64, u8),
    Render(u64),
    List(u64),
    Index,
    Discover,
}

fn step() -> impl proptest::strategy::Strategy<Value = Step> {
    use proptest::prelude::*;
    let entry = proptest::sample::select(vec![ONE, CALLER, TWO, PASSES, common::FORKED]);
    prop_oneof![
        3 => (common::BASE..TEXT, any::<u8>()).prop_map(|(at, byte)| Step::Write(at, byte)),
        2 => entry.clone().prop_map(Step::Render),
        1 => entry.prop_map(Step::List),
        1 => Just(Step::Index),
        1 => Just(Step::Discover),
    ]
}

/// What one question answers, spelled so two programs' answers compare.
fn asked(program: &mut OpenProgram<Literal>, step: &Step) -> String {
    match *step {
        Step::Write(..) => String::new(),
        Step::Render(entry) => format!(
            "{:?}",
            program
                .rendered(entry, r2engine::RenderTier::C)
                .map(|rendering| (rendering.response.output.into_text(), rendering.unread))
        ),
        Step::List(entry) => format!(
            "{:?}",
            program
                .function_listing(entry)
                .map(|listing| (listing.lines.value, listing.refused.is_some()))
        ),
        Step::Index => format!("{:?}", program.references().map(|index| index.value)),
        Step::Discover => format!("{:?}", program.functions()),
    }
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(24))]

    /// The exit the query ADR sets for Q: any interleaving of writes and
    /// questions over the real program inputs answers as a fresh open does.
    #[test]
    fn a_session_answers_as_a_fresh_open_of_its_bytes(
        steps in proptest::collection::vec(step(), 1..16),
    ) {
        let mut program = opened();
        let mut written = Vec::new();
        for step in &steps {
            if let Step::Write(at, byte) = *step {
                program.source_mut().write(at, &[byte]);
                written.push((at, byte));
                continue;
            }
            let mut fresh = Literal::new();
            for (at, byte) in &written {
                fresh.write(*at, &[*byte]);
            }
            let mut fresh = OpenProgram::of(fresh);
            proptest::prop_assert_eq!(asked(&mut program, step), asked(&mut fresh, step));
        }
    }
}
