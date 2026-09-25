//! Where an import stub begins, as the call to it names it.

mod common;

use common::{
    ARM_PLT, ARM_PLT_SLOTS, BASE, Literal, MOVED_STUB, PLT_CALLER, PLT_STUB, import_write,
};
use r2engine::program::{Libc, OpenProgram, PlatformEvidence};
use r2engine::query::{Listing, Stop};

#[test]
fn a_lone_stub_begins_at_its_transfer_not_at_the_pad_before_it() {
    let mut program = OpenProgram::of(Literal::plt());
    let call = program
        .listing(Listing {
            start: PLT_CALLER,
            stop: Stop::After(1),
        })
        .expect("it lists");
    let imports: Vec<(u64, &str)> = program
        .imports()
        .iter()
        .map(|(at, stub)| (*at, stub.symbol.as_str()))
        .collect();
    assert_eq!(imports, [(PLT_STUB, "_Exit")]);
    let named = program.names().of(PLT_STUB).map(|name| name.spelled());
    assert_eq!(named.as_deref(), Some("sym.imp._Exit"), "{:?}", call.value);
    // A lone stub has no neighbour to measure a stride against; its cell runs
    // to the end of the section, which is where every cell is anchored.
    let size = program.names().of(PLT_STUB).map(|name| name.size);
    assert_eq!(size, Some(BASE + 0x20 - PLT_STUB));
}

#[test]
fn a_section_of_stubs_is_known_by_what_it_holds_not_by_its_name() {
    // The same `.plt` under another name still holds nothing but a resolver
    // jump and a jump through the import's slot, so its stub is named.
    let mut program = OpenProgram::of(Literal::plt().renamed(0, ".foo"));
    program.ensure_current().expect("it is current");
    let imports: Vec<(u64, &str)> = program
        .imports()
        .iter()
        .map(|(at, stub)| (*at, stub.symbol.as_str()))
        .collect();
    assert_eq!(imports, [(PLT_STUB, "_Exit")]);
    // The code that calls it makes a call, so it is the program's own and holds no stub.
    assert!(program.imports().range(PLT_CALLER..).next().is_none());
}

#[test]
fn a_stub_that_builds_its_slot_from_two_halves_is_named_for_the_import() {
    let literal = Literal::of_code(MOVED_STUB, &[]).in_arm();
    let mut program = OpenProgram::of(literal.in_plt(0x2000, "_Exit"));
    let listing = Listing {
        start: BASE,
        stop: Stop::After(3),
    };
    let stub = program.listing(listing).expect("it lists");
    // The fold carries `movw` into `movt`, so the load names the slot and the slot names the import.
    let imports = program
        .imports()
        .iter()
        .map(|(at, stub)| (*at, stub.symbol.as_str()));
    assert_eq!(
        imports.collect::<Vec<_>>(),
        [(BASE, "_Exit")],
        "{:?}",
        stub.value
    );
}

#[test]
fn an_arm_plt0_whose_literal_word_decodes_as_a_conditional_instruction_still_holds_stubs() {
    // `andeq` is lifted as a branch to the next instruction around its own
    // effect, which transfers nowhere the straight line does not go; reading
    // it as a branch of the section's own choosing left every ARM `.plt`
    // unnamed.
    let literal = Literal::of_code(ARM_PLT, &[])
        .in_arm()
        .in_plt(ARM_PLT_SLOTS[0], "_Exit")
        .loader_written(import_write(ARM_PLT_SLOTS[1], 4, "abort"))
        // The resolver's two words, which the loader writes with no record naming them.
        .loader_written(r2engine::program::LoaderWrite {
            place: 0x2014,
            width: 8,
            kind: r2engine::program::WriteKind::Unknown,
        });
    let mut program = OpenProgram::of(literal);
    program.ensure_current().expect("it is current");
    let imports: Vec<(u64, &str, u64)> = program
        .imports()
        .iter()
        .map(|(at, stub)| (*at, stub.symbol.as_str(), stub.size))
        .collect();
    // Twelve-byte cells, measured between the two transfers and anchored at the section's end.
    assert_eq!(
        imports,
        [(BASE + 0x14, "_Exit", 12), (BASE + 0x20, "abort", 12)]
    );
}

/// Each parameter's type, as the declaration a call to `import` is read against writes it.
fn declared(import: &str, evidence: &[PlatformEvidence]) -> Option<Vec<String>> {
    let mut program = OpenProgram::of(Literal::plt_importing(import).running_on(evidence));
    // Describing the caller reads its call against the machine's declarations.
    program.function_info(PLT_CALLER).expect("it is described");
    let target = r2engine::native::Program::target_at(&program, PLT_CALLER).expect("a machine");
    let prototype = target.prototypes.get(import)?;
    Some(
        prototype
            .parameters
            .iter()
            .map(|parameter| parameter.spelling.as_written().to_owned())
            .collect(),
    )
}

#[test]
fn a_call_is_read_against_the_c_library_the_container_names_and_no_other() {
    use Libc::{Bionic, Glibc, Musl};
    use PlatformEvidence::{Interpreter, Note, OsAbi};
    let glibc = ["char *", "size_t", "int", "FILE *"]
        .map(str::to_owned)
        .to_vec();
    let bionic = ["char *", "int", "FILE *", "size_t"]
        .map(str::to_owned)
        .to_vec();
    // bionic's dynamic linker in `PT_INTERP` is an Android program, whose
    // `__fgets_chk` takes the stream third; glibc's takes it last. Every ELF
    // was read as glibc's once, so an Android call had its length and its
    // stream swapped.
    assert_eq!(
        declared("__fgets_chk", &[Interpreter(Bionic)]),
        Some(bionic.clone())
    );
    assert_eq!(
        declared("__fgets_chk", &[Note(Bionic), OsAbi(3)]),
        Some(bionic)
    );
    assert_eq!(
        declared("__fgets_chk", &[Interpreter(Glibc), Note(Glibc)]),
        Some(glibc)
    );
    // Nothing stated, two libraries named, a library r2abi declares nothing
    // for, or another system's ABI: only what every library shares applies,
    // so the call has no prototype rather than a guessed one.
    for evidence in [
        &[][..],
        &[Interpreter(Bionic), Note(Glibc)],
        &[Interpreter(Musl)],
        &[Interpreter(Glibc), OsAbi(9)],
    ] {
        assert_eq!(declared("__fgets_chk", evidence), None, "{evidence:?}");
    }
    // What every library declares alike applies with or without any.
    assert!(declared("__memcpy_chk", &[]).is_some());
    // An identifier is looked up as it is: a program's own `_strlen` is not `strlen`.
    assert_eq!(declared("_strlen", &[Interpreter(Glibc)]), None);
}
