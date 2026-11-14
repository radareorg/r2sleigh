//! Conformance per selected cspec (doc/adr-call-boundary.md, S1): each model builds, its row's
//! registers resolve, and its sections, results, ranges and overrides are the cspec's and the ABI's.

use r2abi::{CLibrary, ConventionId, Extension, Kernel, SlotClass};
use r2engine::native::convention_model;
use r2sleigh_lift::profile::LanguageProfile;
use r2source::ConventionModel;
use r2source::convention::{LaneSource, Location, OwnedRange, SectionClass, StackOwner};
use r2source::{SourceTypeKind as K, SourceUnplacedClass as U};
use r2ssa::place::ParamClass as C;

/// The C library a program on `kernel` reads here: glibc, libSystem or Microsoft's.
fn library(kernel: Kernel) -> CLibrary {
    match kernel {
        Kernel::Linux => CLibrary::Glibc,
        Kernel::Darwin => CLibrary::LibSystem,
        Kernel::Windows => CLibrary::Ucrt,
        Kernel::Unknown => CLibrary::Unknown,
    }
}

/// The model of `id` on the embedded machine `sleigh`, reading the cspec compiler `toolchain`.
fn model(
    sleigh: &str,
    toolchain: Option<&str>,
    id: ConventionId,
    kernel: Kernel,
) -> ConventionModel {
    let machine = r2sleigh_lift::embedded_machine(sleigh).expect("an embedded machine");
    let spec = toolchain.map_or(machine.compiler_spec, |id| {
        machine
            .compiler_spec_of(id)
            .expect("the toolchain's specification")
    });
    let profile = LanguageProfile::parse(spec).expect("parses");
    assert!(profile.unknown.is_empty(), "{id:?}: {:?}", profile.unknown);
    let built = convention_model(
        &machine.arch,
        64,
        (kernel, library(kernel), Default::default()),
        &profile,
        id.row(),
    );
    let built = built.unwrap_or_else(|why| panic!("{id:?}: {why}"));
    assert_eq!(
        built.effect_refused(),
        None,
        "{id:?}: the call effect holds"
    );
    // Every register the row names resolves: the frame pointer, `al`, each override lane.
    let row = id.row();
    assert_eq!(
        built.forms.frame_pointer.is_some(),
        row.frame_pointer.is_some(),
        "{id:?}"
    );
    assert_eq!(
        built.forms.count_register.is_some(),
        row.count_register.is_some(),
        "{id:?}"
    );
    let overridden = (built.results.iter()).filter(|lane| lane.stated_by == LaneSource::Override);
    let lanes = row.overrides.iter().map(|item| match item {
        r2abi::SpecOverride::Results { lanes, .. } => lanes.len(),
        r2abi::SpecOverride::Extension { .. } => 0,
    });
    assert_eq!(
        overridden.count(),
        lanes.sum::<usize>(),
        "{id:?}: every result lane resolves"
    );
    built
}

fn classes(model: &ConventionModel) -> Vec<(SectionClass, usize)> {
    (model.sections.iter())
        .map(|section| (section.class, section.locations.len()))
        .collect()
}

fn extensions(model: &ConventionModel, class: SlotClass) -> Vec<Extension> {
    let located = model
        .sections
        .iter()
        .flat_map(|section| section.locations.iter());
    located
        .filter_map(|location| match *location {
            Location::Register {
                class: of,
                extension,
                ..
            } if of == class => Some(extension),
            _ => None,
        })
        .collect()
}

fn model_of_sysv() -> ConventionModel {
    model("x86-64", None, ConventionId::SysVAmd64, Kernel::Linux)
}

/// x86-64-gcc and SysV: six integer and eight float registers apart, the stack past the return
/// address, and SysV 3.2.3's `st0`/`st1` results beside the cspec's four.
#[test]
fn the_sysv_model_is_x86_64_gcc_joined_with_the_psabi() {
    let model = model_of_sysv();
    assert_eq!(
        classes(&model),
        [
            (SectionClass::Integer, 6),
            (SectionClass::Float, 8),
            (SectionClass::Stack { first: 0, step: 8 }, 0)
        ]
    );
    let stated = (model.results.iter()).filter(|lane| lane.stated_by == LaneSource::Specification);
    assert_eq!(stated.count(), 4, "XMM0_Qa, XMM1_Qa, RAX, RDX");
    assert_eq!(model.forms.red_zone, 128);
    assert!(model.forms.guard.is_some(), "glibc's fs:0x28");
    assert!(model.owned.contains(&OwnedRange::ReturnAddress(0..8)));
}

/// x86-64-win and Microsoft x64: four shared positions, the stack past the 32-byte home area,
/// which `localrange` gives the callee and the ABI splits into one home per position.
#[test]
fn the_win64_model_shares_positions_and_owns_the_home_area() {
    let model = model(
        "x86-64",
        Some("windows"),
        ConventionId::Win64,
        Kernel::Windows,
    );
    assert_eq!(
        classes(&model),
        [
            (SectionClass::Shared, 8),
            (SectionClass::Stack { first: 32, step: 8 }, 0)
        ]
    );
    let homes = (model.owned.iter())
        .filter_map(|owned| match owned {
            OwnedRange::Home { position, at } => Some((*position, at.clone())),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(homes, [(0, 8..16), (1, 16..24), (2, 24..32), (3, 32..40)]);
    let above = |owned: &OwnedRange| matches!(owned, OwnedRange::Callee(at) if at.end > 0);
    assert!(!model.owned.iter().any(above), "{:?}", model.owned);
    assert_eq!(model.owner(8), StackOwner::Home { position: 0 });
    assert_eq!(model.owner(39), StackOwner::Home { position: 3 });
    assert_eq!(
        model.owner(40),
        StackOwner::Caller,
        "the first stack argument"
    );
    assert_eq!(model.owner(0), StackOwner::ReturnAddress);
    assert_eq!(model.owner(-8), StackOwner::Callee);
    let sysv = model_of_sysv();
    assert_eq!(sysv.owner(8), StackOwner::Caller, "SysV has no home");
    assert_eq!(model.forms.red_zone, 0);
    assert!(model.forms.count_register.is_none() && model.forms.save_area.is_none());
}

/// AARCH64 and AAPCS64: x0 to x7 and v0 to v7, x8 the hidden result pointer, and C.16's unspecified
/// upper bits over the cspec's `extension="zero"`.
#[test]
fn the_aapcs64_model_overrides_the_cspec_s_zero_extension() {
    let model = model("aarch64", None, ConventionId::Aapcs64, Kernel::Linux);
    assert_eq!(
        classes(&model)[..2],
        [(SectionClass::Integer, 8), (SectionClass::Float, 8)]
    );
    assert!(model.hidden_return.is_some(), "x8");
    let integer = extensions(&model, SlotClass::Integer);
    assert!(
        integer.iter().all(|e| *e == Extension::Unspecified),
        "{integer:?}"
    );
    let x0 = model
        .results
        .iter()
        .find(|lane| lane.class == SlotClass::Integer);
    assert_eq!(x0.map(|lane| lane.extension), Some(Extension::Unspecified));
    assert!(model.forms.save_area.is_some() && !model.forms.variadic_on_stack);
}

/// AAPCS64 6.1.2: a call keeps the low 8 bytes of `v8` to `v15`, lanes of their vector roots.
#[test]
fn the_aapcs64_model_preserves_d8_to_d15_as_lanes() {
    let model = model("aarch64", None, ConventionId::Aapcs64, Kernel::Linux);
    let machine = r2sleigh_lift::embedded_machine("aarch64").expect("an embedded machine");
    let d8 = r2sleigh_lift::lifted_register_storage(&machine.arch, "d8").expect("d8");
    let lane = (model.preserved.iter())
        .find(|lane| lane.narrowed() == d8)
        .unwrap_or_else(|| panic!("{:?}", model.preserved));
    assert_eq!(lane.bytes, 0..8);
    assert!(lane.storage.size > 8, "{lane:?}");
    let lanes = (model.preserved.iter()).filter(|lane| lane.storage.size > lane.bytes.len() as u32);
    assert_eq!(lanes.count(), 8, "{:?}", model.preserved);
}

/// AARCH64_apple and Apple arm64: the variadic tail on the stack, no save area, x18 reserved, and
/// the caller's extension to 32 bits.
#[test]
fn the_apple_arm64_model_extends_arguments_to_32_bits() {
    let model = model(
        "aarch64",
        Some("apple"),
        ConventionId::AppleArm64,
        Kernel::Darwin,
    );
    assert!(model.forms.variadic_on_stack && model.forms.save_area.is_none());
    let integer = extensions(&model, SlotClass::Integer);
    assert!(
        integer.iter().all(|e| *e == Extension::IntType),
        "{integer:?}"
    );
    assert!(!model.reserved.is_empty(), "x18");
}

/// The lane set (D305): SysV's six lanes, which follows which, x87 empty at entry, the set cited
/// complete; AAPCS64 pairs x1 with x0 and q1 to q3 in turn; a model whose row cites none has none.
#[test]
fn a_result_lane_set_states_entries_pairs_and_its_completeness() {
    use r2source::convention::LaneEntry;
    let lane = |model: &ConventionModel, offset: u64| {
        let at = (model.results.iter())
            .position(|lane| lane.storage.offset == offset)
            .expect("a lane");
        (
            model.results[at].entry,
            model.results[at]
                .follows
                .map(|first| model.results[first].storage.offset),
        )
    };
    let sysv = model_of_sysv();
    assert!(sysv.results_complete.is_some());
    assert_eq!(lane(&sysv, 0x0), (LaneEntry::Scratch, None), "rax");
    assert_eq!(
        lane(&sysv, 0x10),
        (LaneEntry::Input, Some(0x0)),
        "rdx after rax"
    );
    assert_eq!(
        lane(&sysv, 0x1240),
        (LaneEntry::Input, Some(0x1200)),
        "xmm1 after xmm0"
    );
    assert_eq!(lane(&sysv, 0x1100).0, LaneEntry::Empty, "st0");
    let aapcs64 = model("aarch64", None, ConventionId::Aapcs64, Kernel::Linux);
    assert!(aapcs64.results_complete.is_some());
    assert_eq!(
        lane(&aapcs64, 0x4008),
        (LaneEntry::Input, Some(0x4000)),
        "x1 after x0"
    );
    assert!(ConventionId::I386Cdecl.row().results.is_none());
    assert!(ConventionId::Aapcs32.row().results.is_none());
}

/// A call from an `ms_abi` function in an ELF reaches a callee under either convention, so it
/// keeps only what both preserve and reads what either reads (doc/adr-call-boundary.md, S20).
#[test]
fn a_call_under_either_convention_keeps_only_what_both_preserve() {
    let machine = r2sleigh_lift::embedded_machine("x86-64").expect("an embedded machine");
    let register = |name: &str| {
        let found = (machine.arch.registers.iter()).find(|it| it.name.eq_ignore_ascii_case(name));
        let found = found.unwrap_or_else(|| panic!("{name}"));
        r2source::CanonicalStorageId {
            space: r2source::CanonicalStorageSpace::Register,
            offset: found.offset,
            size: found.size,
        }
    };
    let win64 = model(
        "x86-64",
        Some("windows"),
        ConventionId::Win64,
        Kernel::Linux,
    );
    let own = &win64;
    let either = win64.either(&model_of_sysv()).expect("the join");
    for name in ["rsi", "rdi", "xmm6"] {
        assert!(
            own.preserves(register(name)),
            "{name}: Microsoft x64 keeps it"
        );
        assert!(either.clobbers(register(name)), "{name}: SysV may not");
    }
    for name in ["rbx", "rbp", "r12"] {
        assert!(either.preserves(register(name)), "{name}");
    }
    let reads = either.call_reads().expect("the join's reads");
    for name in ["rcx", "rdx", "rdi", "rsi", "al"] {
        assert!(reads.contains(&register(name)), "{name}");
    }
}

/// The specifications `assemble` reads a convention under: its compiler's where the row names
/// one, else the default, Windows' and Apple's.
fn specifications(
    machine: &r2sleigh_lift::EmbeddedMachine,
    row: &r2abi::ConventionRow,
) -> Vec<(&'static str, Option<&'static str>)> {
    match row.cspec.toolchain {
        r2abi::Toolchain::Compiler(compiler) => {
            vec![(compiler, machine.compiler_spec_of(compiler))]
        }
        r2abi::Toolchain::Container => vec![
            ("default", Some(machine.compiler_spec)),
            ("windows", machine.compiler_spec_of("windows")),
            ("apple", machine.compiler_spec_of("apple")),
        ],
    }
}

/// A specification parsed and narrowed to the row's prototype, where it has it.
fn profile_of(spec: Option<&str>, row: &r2abi::ConventionRow) -> Option<LanguageProfile> {
    let profile = LanguageProfile::parse(spec?).ok()?;
    match row.cspec.prototype {
        Some(prototype) => profile.under(prototype),
        None => Some(profile),
    }
}

const KERNELS: [Kernel; 4] = [
    Kernel::Linux,
    Kernel::Darwin,
    Kernel::Windows,
    Kernel::Unknown,
];

/// Every model the native path builds on one machine, named `machine/compiler/id/kernel`.
fn built_on(sleigh: &str, bits: u32) -> Vec<(String, ConventionModel)> {
    let machine = r2sleigh_lift::embedded_machine(sleigh).expect("an embedded machine");
    let mut built = Vec::new();
    let rows = ConventionId::ALL.map(ConventionId::row);
    let read = rows.iter().flat_map(|row| {
        let profiles = specifications(&machine, row).into_iter();
        profiles.filter_map(move |(compiler, spec)| Some((row, compiler, profile_of(spec, row)?)))
    });
    for (row, compiler, profile) in read {
        for kernel in KERNELS {
            let name = format!("{sleigh}/{compiler}/{:?}/{kernel:?}", row.id);
            // Each container form a row can name: a load-config cookie and a linked guard.
            let guards = r2engine::native::ContainerGuards {
                cookie: Some(0x1000),
                linked: Some(r2source::SourceLinkedGuard {
                    copy: Some(0x1010),
                    slots: Box::new([0x1018]),
                    slot_width: bits / 8,
                    width: bits / 8,
                }),
            };
            let at = (kernel, library(kernel), guards);
            if let Ok(model) = convention_model(&machine.arch, bits, at, &profile, row) {
                built.push((name, model));
            }
        }
    }
    built
}

/// Every join `AnyCall` can form of two models under one kernel builds.
fn joins_build(built: &[(String, ConventionModel)]) {
    let kernel = |name: &str| name.rsplit('/').next().map(str::to_owned);
    let pairs = built
        .iter()
        .flat_map(|one| built.iter().map(move |other| (one, other)));
    let pairs = pairs.filter(|((one, _), (other, _))| one != other && kernel(one) == kernel(other));
    for ((one, model), (other, with)) in pairs {
        let join = model.either(with);
        join.unwrap_or_else(|why| panic!("{one} with {other}: {why:?}"));
    }
}

/// Every model the native path builds on the nine selected cspecs, and every join `AnyCall` forms
/// of two of them, builds with its effect; a refused effect would keep nothing.
#[test]
fn every_native_model_and_join_builds_with_its_effect() {
    let mut specifications = std::collections::BTreeSet::new();
    let mut refused = Vec::new();
    for (sleigh, bits) in [("x86-64", 64), ("x86", 32), ("aarch64", 64)] {
        let built = built_on(sleigh, bits);
        for (name, model) in &built {
            let compiler = name.split('/').nth(1).unwrap_or_default();
            specifications.insert(format!("{sleigh}/{compiler}"));
            if let Some(why) = model.effect_refused() {
                refused.push(format!("{name}: {why:?}"));
                assert!(model.clobbered().is_none() && model.call_reads().is_none());
                assert!(model.preserved_registers().is_empty() && model.stack_bound().is_none());
            }
        }
        joins_build(&built);
    }
    let selected = [
        "x86-64/gcc",
        "x86-64/windows",
        "x86-64/golang",
        "x86/default",
        "x86/windows",
        "aarch64/default",
        "aarch64/apple",
        "aarch64/windows",
        "aarch64/golang",
    ];
    for specification in selected {
        assert!(
            specifications.contains(specification),
            "{specification}: {specifications:?}"
        );
    }
    // Go's arm64 specification names x18 unaffected, which Darwin reserves: x18 is reserved (D274).
    assert_eq!(refused, Vec::<String>::new());
}

/// One node per class `ParamClass::of` answers at a 64-bit pointer, and that class.
fn classed_nodes() -> Vec<((K, u64), C)> {
    let int = |bits| (K::SignedInteger, bits);
    let pointer = K::Pointer {
        target_type_id: 2,
        const_target: false,
    };
    let array = K::Array {
        element_type_id: 2,
        count: Some(4),
    };
    vec![
        (int(8), C::Integer(1)),
        (int(16), C::Integer(2)),
        (int(32), C::Integer(4)),
        (int(64), C::Integer(8)),
        ((K::UnsignedInteger, 32), C::Integer(4)),
        ((K::Char { signed: None }, 8), C::Integer(1)),
        ((pointer, 64), C::Integer(8)),
        ((K::Float, 32), C::Float(4)),
        ((K::Float, 64), C::Float(8)),
        ((K::Float, 16), C::Unplaced(U::Float(16))),
        ((K::Float, 80), C::Unplaced(U::Float(80))),
        ((K::Float, 128), C::Unplaced(U::Float(128))),
        (int(128), C::Unplaced(U::WideInteger(128))),
        (
            (K::Struct { aggregate_id: 0 }, 32),
            C::Unplaced(U::Aggregate),
        ),
        (
            (K::Union { aggregate_id: 1 }, 32),
            C::Unplaced(U::Aggregate),
        ),
        ((array, 128), C::Unplaced(U::Aggregate)),
        ((K::Opaque { tag_id: 0 }, 0), C::Unplaced(U::Unsized)),
        ((K::Void, 0), C::Unplaced(U::Unsized)),
        ((K::Code { signature_id: 0 }, 0), C::Unplaced(U::Unsized)),
    ]
}

/// Those nodes as one graph, each at its natural alignment and the array at its element's.
fn classed_graph(nodes: &[((K, u64), C)]) -> r2source::SourceTypeGraph {
    use r2source::{
        SourceAggregateLayout, SourceAggregateMember, SourceCodeSignature, SourceOpaqueTag,
        SourceTagKeyword, SourceType, SourceTypeGraphParts,
    };
    let align = |kind: &K, bits: u64| match (kind, bits) {
        (K::Array { .. }, _) => 32,
        (_, 0) => 0,
        (_, bits) => (1u64 << bits.trailing_zeros()).max(8),
    };
    let types = (nodes.iter().enumerate()).map(|(id, ((kind, bits), _))| {
        SourceType::new(id as u32, *kind, *bits, align(kind, *bits))
    });
    let member = || [SourceAggregateMember::new(0, 2, 0, 32, "x")];
    r2source::SourceTypeGraph::from_parts(SourceTypeGraphParts {
        types: types.collect(),
        aggregates: vec![
            SourceAggregateLayout::new(0, 13, 32, 32, "s", member()),
            SourceAggregateLayout::new(1, 14, 32, 32, "u", member()),
        ],
        signatures: vec![SourceCodeSignature::new(0, 17, [2], false, true)],
        opaque_tags: vec![SourceOpaqueTag::new(0, SourceTagKeyword::Struct, "FILE")],
        ..SourceTypeGraphParts::default()
    })
    .expect("a graph")
}

/// Each class alone takes the first register of its own class or floors, and an integer, a double,
/// an integer share positions on Microsoft x64 only.
fn places_each_class(name: &str, model: &ConventionModel, nodes: &[((K, u64), C)]) {
    use r2source::SourceParameterLocation;
    use r2ssa::place::place;
    let at = |class, position: usize, bytes: u32| {
        let register = model.argument(class, position).expect("a register");
        let size = match class {
            SlotClass::Float => bytes.min(register.size),
            _ => register.size,
        };
        SourceParameterLocation::Register(r2source::CanonicalStorageId { size, ..register })
    };
    for (_, class) in nodes {
        let placed = place(model, &[*class]);
        match *class {
            C::Integer(_) => assert_eq!(placed.locations, [at(SlotClass::Integer, 0, 8)]),
            C::Float(bytes) => assert_eq!(
                placed.locations,
                [at(SlotClass::Float, 0, u32::from(bytes))],
                "{name}"
            ),
            C::Unplaced(why) => {
                assert!(placed.locations.is_empty(), "{name}");
                assert_eq!(placed.floor, Some(why), "{name}");
            }
        }
    }
    let placed = place(model, &[C::Integer(4), C::Float(8), C::Integer(8)]);
    let shared = name == "Microsoft x64";
    let expected = [
        at(SlotClass::Integer, 0, 8),
        at(SlotClass::Float, usize::from(shared), 8),
        at(SlotClass::Integer, if shared { 2 } else { 1 }, 8),
    ];
    assert_eq!(placed.locations, expected, "{name}");
}

/// Every class `ParamClass::of` answers, and where SysV, Microsoft x64 and AAPCS64 place it (S32a).
#[test]
fn param_class_of_answers_each_class_and_each_model_places_it() {
    let nodes = classed_nodes();
    let graph = classed_graph(&nodes);
    let classes = (0..nodes.len() as u32).map(|id| C::of(&graph, id, 64));
    assert!(classes.eq(nodes.iter().map(|(_, class)| *class)));
    let missing = C::of(&graph, nodes.len() as u32, 64);
    assert_eq!(missing, C::Unplaced(U::Unsized));
    let ilp32 = C::of(&graph, 3, 32);
    assert_eq!(ilp32, C::Unplaced(U::WideInteger(64)));
    let win64 = model(
        "x86-64",
        Some("windows"),
        ConventionId::Win64,
        Kernel::Windows,
    );
    let aapcs64 = model("aarch64", None, ConventionId::Aapcs64, Kernel::Linux);
    places_each_class("SysV", &model_of_sysv(), &nodes);
    places_each_class("Microsoft x64", &win64, &nodes);
    places_each_class("AAPCS64", &aapcs64, &nodes);
}
