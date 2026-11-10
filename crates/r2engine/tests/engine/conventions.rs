//! Conformance per selected cspec (doc/adr-call-boundary.md, S1): each model builds, its row's
//! registers resolve, and its sections, results, ranges and overrides are the cspec's and the ABI's.

use r2abi::{CLibrary, ConventionId, Extension, Kernel, SlotClass};
use r2engine::native::convention_model;
use r2sleigh_lift::profile::LanguageProfile;
use r2source::ConventionModel;
use r2source::convention::{LaneSource, Location, OwnedRange, SectionClass, StackOwner};

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
        (kernel, library(kernel)),
        &profile,
        id.row(),
    );
    let built = built.unwrap_or_else(|why| panic!("{id:?}: {why}"));
    assert!(built.call_effect().is_ok(), "{id:?}: the call effect holds");
    assert!(built.convention_slots().is_ok(), "{id:?}: the slots hold");
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
