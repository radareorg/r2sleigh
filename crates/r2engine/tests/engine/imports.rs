//! Where an import stub begins, as the call to it names it.

use crate::common;

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
    let held = program.imports().stubs.clone();
    let imports: Vec<(u64, &str)> = held
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

/// A static image's `.plt` holds only `IRELATIVE` stubs: no relocation binds an import, yet each stub is code
/// the loader sends through a word it fills, so it is a function start and no body may absorb it.
#[test]
fn a_stub_through_a_resolver_slot_is_a_start_in_an_image_that_binds_no_import() {
    let program = OpenProgram::of(Literal::plt_resolved());
    program.loaded().expect("it is current");
    let linkage = program.imports();
    assert!(linkage.stubs.is_empty(), "{:?}", linkage.stubs);
    assert_eq!(
        linkage.unnamed.keys().copied().collect::<Vec<_>>(),
        [PLT_STUB]
    );
}

/// PLT0's padding and a stub's landing pad both lift to nothing, so what
/// does nothing does not say where the stub begins; the section's stated
/// alignment does. (`printf@plt` in a clang -O2 build was named four bytes
/// early, and the calls to it found no prototype.)
#[test]
fn a_lone_stub_begins_on_its_section_alignment_not_at_padding_that_does_nothing() {
    let program = OpenProgram::of(Literal::plt_nop_padded());
    program.loaded().expect("it is current");
    let held = program.imports().stubs.clone();
    let imports: Vec<(u64, &str, u64)> = held
        .iter()
        .map(|(at, stub)| (*at, stub.symbol.as_str(), stub.size))
        .collect();
    assert_eq!(imports, [(PLT_STUB, "_Exit", BASE + 0x20 - PLT_STUB)]);
}

#[test]
fn a_section_of_stubs_is_known_by_what_it_holds_not_by_its_name() {
    // The same `.plt` under another name still holds nothing but a resolver
    // jump and a jump through the import's slot, so its stub is named.
    let program = OpenProgram::of(Literal::plt().renamed(0, ".foo"));
    program.loaded().expect("it is current");
    let held = program.imports().stubs.clone();
    let imports: Vec<(u64, &str)> = held
        .iter()
        .map(|(at, stub)| (*at, stub.symbol.as_str()))
        .collect();
    assert_eq!(imports, [(PLT_STUB, "_Exit")]);
    // The code that calls it makes a call, so it is the program's own and holds no stub.
    assert!(program.imports().stubs.range(PLT_CALLER..).next().is_none());
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
    let held = program.imports().stubs.clone();
    let imports = held.iter().map(|(at, stub)| (*at, stub.symbol.as_str()));
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
            encoding: r2engine::program::Encoding::Word,
        });
    let program = OpenProgram::of(literal);
    program.loaded().expect("it is current");
    let held = program.imports().stubs.clone();
    let imports: Vec<(u64, &str, u64)> = held
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
    declared_in(Literal::plt_importing(import).running_on(evidence), import)
}

fn declared_in(program: Literal, import: &str) -> Option<Vec<String>> {
    let mut program = OpenProgram::of(program);
    // Describing the caller reads its call against the machine's declarations.
    program.function_info(PLT_CALLER).expect("it is described");
    let target = r2engine::native::Program::target_at(&program, PLT_CALLER).expect("a machine");
    let row = target.imports.bind(import).ok()?;
    let parameters = target.imports.rows().prototype(row).parameters.iter();
    Some(
        parameters
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
    // What every library declares alike applies with or without any evidence, where `DT_NEEDED`
    // names one C library; with none named, an unversioned import binds to no row.
    assert!(declared("__memcpy_chk", &[]).is_some());
    let unlinked = Literal::plt_importing("__memcpy_chk").needing(&[]);
    assert_eq!(declared_in(unlinked, "__memcpy_chk"), None);
    let two = Literal::plt_importing("__memcpy_chk").needing(&["libc.so.6", "libc.so"]);
    assert_eq!(declared_in(two, "__memcpy_chk"), None);
    // An identifier is looked up as it is: a program's own `_strlen` is not `strlen`.
    assert_eq!(declared("_strlen", &[Interpreter(Glibc)]), None);
}

/// The helper's lazy entries all jump to its header, which jumps through the binder's slot: the
/// header is the section's resolver and no import's stub, as ELF's PLT0 is.
#[test]
fn a_header_the_section_s_entries_jump_to_is_no_import_s_stub() {
    let program = OpenProgram::of(Literal::stub_helper());
    let named = program.imports().stubs.clone();
    assert!(
        named.values().all(|stub| stub.symbol != "dyld_stub_binder"),
        "{named:x?}"
    );
}

/// A shared object has no `PT_INTERP`: `DT_NEEDED libc.so.6` with a `GLIBC_*` need on it names
/// glibc (libz.so's 22 `__stack_chk_fail` calls, hand audit 3.2.4); the soname alone names none.
#[test]
fn a_glibc_version_need_names_the_c_library_of_a_shared_object() {
    let glibc = ["char *", "size_t", "int", "FILE *"]
        .map(str::to_owned)
        .to_vec();
    let needing =
        Literal::plt_importing("__fgets_chk").needing_versions("libc.so.6", &["GLIBC_2.2.5"]);
    assert_eq!(declared_in(needing, "__fgets_chk"), Some(glibc));
    // musl and bionic also ship a `libc.so`, and no version need names glibc there.
    assert_eq!(declared("__fgets_chk", &[]), None);
}

/// `caller: call import; mov eax, 7; ret`, then the import's stub at [`common::STUB`].
fn calling_then_seven() -> &'static [u8] {
    let mut code = vec![0xcc; 0xa0];
    let call = (common::STUB - (BASE + 5)) as u32;
    code[0] = 0xe8;
    code[1..5].copy_from_slice(&call.to_le_bytes());
    code[5..0x0b].copy_from_slice(&[0xb8, 0x07, 0x00, 0x00, 0x00, 0xc3]);
    code[0x90..0x96].copy_from_slice(&common::JUMP_STUB);
    code[0x98..0xa0].fill(0);
    Box::leak(code.into_boxed_slice())
}

/// glibc 2.39 `<setjmp.h>` declares `longjmp` `__noreturn__` (D495): the caller's body ends at the
/// call, and the code after it is no block of it.
#[test]
fn code_after_a_longjmp_import_call_is_not_in_the_body() {
    for import in ["longjmp", "_longjmp", "siglongjmp"] {
        let literal = common::Literal::of_code(calling_then_seven(), &[("caller", BASE, 0x0b)])
            .importing(import)
            .running_on(common::GLIBC);
        let info = (OpenProgram::of(literal).function_info(BASE)).expect("it is described");
        let blocks = (info.blocks.iter()).map(|block| (block.addr, block.size));
        assert_eq!(blocks.collect::<Vec<_>>(), [(BASE, 5)], "{import}");
    }
}

/// AArch64 linkage code no section header states: PLT0 at 0x1000 through GOT[2], cells at 0x1020 and
/// 0x1030 through lazy slots whose file words are PLT0, then `caller: mov x0, #1; b 0x1020`.
const LAZY_PLT: &[u8] = &[
    0xf0, 0x7b, 0xbf, 0xa9, // 0x1000 stp x16, x30, [sp, #-16]!
    0x10, 0x00, 0x00, 0x90, // 0x1004 adrp x16, 0x1000
    0x11, 0x32, 0x40, 0xf9, // 0x1008 ldr x17, [x16, #0x60]
    0x10, 0x82, 0x01, 0x91, // 0x100c add x16, x16, #0x60
    0x20, 0x02, 0x1f, 0xd6, // 0x1010 br x17
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, // 0x1014 nop x3
    0x10, 0x00, 0x00, 0x90, // 0x1020 adrp x16, 0x1000
    0x11, 0x36, 0x40, 0xf9, // 0x1024 ldr x17, [x16, #0x68]
    0x10, 0xa2, 0x01, 0x91, // 0x1028 add x16, x16, #0x68
    0x20, 0x02, 0x1f, 0xd6, // 0x102c br x17
    0x10, 0x00, 0x00, 0x90, // 0x1030 adrp x16, 0x1000
    0x11, 0x3a, 0x40, 0xf9, // 0x1034 ldr x17, [x16, #0x70]
    0x10, 0xc2, 0x01, 0x91, // 0x1038 add x16, x16, #0x70
    0x20, 0x02, 0x1f, 0xd6, // 0x103c br x17
    0x20, 0x00, 0x80, 0xd2, // 0x1040 caller: mov x0, #1
    0xf7, 0xff, 0xff, 0x17, // 0x1044 b 0x1020
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5,
    0x1f, 0x20, 0x03, 0xd5, 0x1f, 0x20, 0x03, 0xd5, // 0x1048 nop x6
    0, 0, 0, 0, 0, 0, 0, 0, // 0x1060 GOT[2]
    0x00, 0x10, 0, 0, 0, 0, 0, 0, // 0x1068 a lazy slot: PLT0
    0x00, 0x10, 0, 0, 0, 0, 0, 0, // 0x1070 a lazy slot: PLT0
];

/// Where no section header states the linkage code, the lazy slots (file words at PLT[0], AAELF64)
/// name each cell's import, and a tail branch to one ends the caller (libarm64.so 0x6c0; D530).
#[test]
fn a_stub_no_section_states_is_found_from_its_lazy_slot() {
    let (caller, got) = (BASE + 0x40, BASE + 0x60);
    // An empty `.text`: no section holds the code, so the executable mapping does (libarm64.so).
    let literal = Literal::of_code(LAZY_PLT, &[("caller", caller, 8)])
        .in_aarch64()
        .text_ending(BASE)
        .loader_written(import_write(got + 8, 8, "_Exit"))
        .loader_written(import_write(got + 0x10, 8, "abort"))
        .loader_written(r2engine::program::LoaderWrite {
            place: got,
            width: 8,
            kind: r2engine::program::WriteKind::Reserved,
            encoding: r2engine::program::Encoding::Word,
        });
    let mut program = OpenProgram::of(literal);
    let held = program.imports().stubs.clone();
    let imports = held
        .iter()
        .map(|(at, stub)| (*at, stub.symbol.as_str(), stub.size));
    let expected = [(BASE + 0x20, "_Exit", 0x10), (BASE + 0x30, "abort", 0x10)];
    assert_eq!(imports.collect::<Vec<_>>(), expected);
    let info = program.function_info(caller).expect("it is described");
    let blocks = (info.blocks.iter()).map(|block| (block.addr, block.size));
    assert_eq!(blocks.collect::<Vec<_>>(), [(caller, 8)]);
}

/// `rel32` from the end of an instruction at `end` to `to`, little-endian.
fn rel(end: u64, to: u64) -> [u8; 4] {
    (to.wrapping_sub(end) as u32).to_le_bytes()
}

/// x86-64 linkage code no section header states, its lazy words at each stub's own `pushq`: PLT0 at
/// 0x1000 through GOT[2], stubs at 0x1010, 0x1020, 0x1030, `caller: mov edi, 1; jmp 0x1010` at 0x1040,
/// GOT at 0x1050.
fn x86_lazy_plt() -> &'static [u8] {
    let (got, mut code) = (BASE + 0x50, vec![0xcc_u8; 0x80]);
    code[0..2].copy_from_slice(&[0xff, 0x35]); // push [GOT+8]
    code[2..6].copy_from_slice(&rel(BASE + 6, got + 8));
    code[6..8].copy_from_slice(&[0xff, 0x25]); // jmp [GOT+16]
    code[8..0xc].copy_from_slice(&rel(BASE + 0xc, got + 0x10));
    code[0xc..0x10].copy_from_slice(&[0x0f, 0x1f, 0x40, 0x00]);
    for index in 0..3_u8 {
        let (at, slot) = (
            0x10 + 0x10 * usize::from(index),
            got + 0x18 + 8 * u64::from(index),
        );
        let stub = BASE + at as u64;
        code[at..at + 2].copy_from_slice(&[0xff, 0x25]);
        code[at + 2..at + 6].copy_from_slice(&rel(stub + 6, slot));
        code[at + 6..at + 11].copy_from_slice(&[0x68, index, 0, 0, 0]);
        code[at + 11] = 0xe9;
        code[at + 12..at + 16].copy_from_slice(&rel(stub + 16, BASE));
        let word = (stub + 6).to_le_bytes();
        let held = (slot - BASE) as usize;
        code[held..held + 8].copy_from_slice(&word);
    }
    code[0x40..0x45].copy_from_slice(&[0xbf, 1, 0, 0, 0]);
    code[0x45] = 0xe9;
    code[0x46..0x4a].copy_from_slice(&rel(BASE + 0x4a, BASE + 0x10));
    code[0x50..0x68].fill(0);
    Box::leak(code.into_boxed_slice())
}

/// The same linkage code built for IBT: lazy words at `.plt` entries `endbr64; push; bnd jmp PLT0`,
/// the slots read by `.plt.sec` at 0x1030 and 0x1040; `caller` at 0x1050, GOT at 0x1060.
fn x86_ibt_plt() -> &'static [u8] {
    let (got, mut code) = (BASE + 0x60, vec![0xcc_u8; 0x88]);
    code[0..2].copy_from_slice(&[0xff, 0x35]);
    code[2..6].copy_from_slice(&rel(BASE + 6, got + 8));
    code[6..9].copy_from_slice(&[0xf2, 0xff, 0x25]); // bnd jmp [GOT+16]
    code[9..0xd].copy_from_slice(&rel(BASE + 0xd, got + 0x10));
    code[0xd..0x10].copy_from_slice(&[0x0f, 0x1f, 0x00]);
    for index in 0..2_u8 {
        let (at, slot) = (
            0x10 + 0x10 * usize::from(index),
            got + 0x18 + 8 * u64::from(index),
        );
        let entry = BASE + at as u64;
        code[at..at + 4].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa]);
        code[at + 4..at + 9].copy_from_slice(&[0x68, index, 0, 0, 0]);
        code[at + 9..at + 11].copy_from_slice(&[0xf2, 0xe9]); // bnd jmp PLT0
        code[at + 11..at + 15].copy_from_slice(&rel(entry + 15, BASE));
        code[at + 15] = 0x90;
        let sec = at + 0x20;
        let stub = BASE + sec as u64;
        code[sec..sec + 4].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa]);
        code[sec + 4..sec + 7].copy_from_slice(&[0xf2, 0xff, 0x25]); // bnd jmp [slot]
        code[sec + 7..sec + 11].copy_from_slice(&rel(stub + 11, slot));
        code[sec + 11..sec + 16].copy_from_slice(&[0x0f, 0x1f, 0x44, 0x00, 0x00]);
        let held = (slot - BASE) as usize;
        code[held..held + 8].copy_from_slice(&entry.to_le_bytes());
    }
    code[0x50..0x55].copy_from_slice(&[0xbf, 1, 0, 0, 0]);
    code[0x55] = 0xe9;
    code[0x56..0x5a].copy_from_slice(&rel(BASE + 0x5a, BASE + 0x30));
    code[0x60..0x78].fill(0);
    Box::leak(code.into_boxed_slice())
}

/// The lazy linkage `literal` declares at `got`: GOT[1] and GOT[2] reserved, then one slot per import.
fn lazily_linked(literal: Literal, got: u64, imports: &[&str]) -> Literal {
    let reserved = |place| r2engine::program::LoaderWrite {
        place,
        width: 8,
        kind: r2engine::program::WriteKind::Reserved,
        encoding: r2engine::program::Encoding::Word,
    };
    let literal = literal
        .text_ending(BASE)
        .loader_written(reserved(got + 8))
        .loader_written(reserved(got + 0x10));
    (imports.iter().enumerate()).fold(literal, |literal, (index, import)| {
        literal.loader_written(import_write(got + 0x18 + 8 * index as u64, 8, import))
    })
}

/// An x86-64 lazy word is the address of the `pushq` after its own stub's jump (psABI 1.0, 5.2,
/// "Procedure Linkage Table"); the instruction ending there jumping through the slot names the stub (D636).
#[test]
fn an_x86_64_stub_no_section_states_is_the_jump_ending_at_its_lazy_word() {
    let caller = BASE + 0x40;
    let literal = Literal::of_code(x86_lazy_plt(), &[("caller", caller, 10)]);
    let literal = lazily_linked(literal, BASE + 0x50, &["_Exit", "abort", "puts"]);
    let mut program = OpenProgram::of(literal);
    let held = program.imports().stubs.clone();
    let imports = held
        .iter()
        .map(|(at, stub)| (*at, stub.symbol.as_str(), stub.size));
    let expected = [
        (BASE + 0x10, "_Exit", 0x10),
        (BASE + 0x20, "abort", 0x10),
        (BASE + 0x30, "puts", 0x10),
    ];
    assert_eq!(imports.collect::<Vec<_>>(), expected);
    let info = program.function_info(caller).expect("it is described");
    let blocks = (info.blocks.iter()).map(|block| (block.addr, block.size));
    assert_eq!(blocks.collect::<Vec<_>>(), [(caller, 10)]);
}

/// Under IBT the lazy word is a `.plt` entry whose preceding instruction is padding, and no word is
/// PLT0: neither reading proves a stub, so none is named (default-deny).
#[test]
fn an_ibt_layout_no_section_states_names_no_stub() {
    let literal = Literal::of_code(x86_ibt_plt(), &[("caller", BASE + 0x50, 10)]);
    let program = OpenProgram::of(lazily_linked(literal, BASE + 0x60, &["_Exit", "abort"]));
    program.loaded().expect("it is current");
    let named = program.imports().stubs.clone();
    assert!(named.is_empty(), "{named:x?}");
}
