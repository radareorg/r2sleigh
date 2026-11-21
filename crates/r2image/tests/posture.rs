//! How an image is linked and protected, each expectation as `readelf -lW -d` and radare2's `i` state it.

use r2image::{Image, LoadBase, Posture, Relro};

fn posture(bytes: &[u8]) -> Posture {
    let image = Image::parse(bytes.to_vec()).expect("the fixture parses");
    image.container().posture.clone()
}

#[test]
fn a_dynamic_executable_states_its_interpreter_and_a_full_relro() {
    let posture = posture(include_bytes!("../../../tests/fixtures/rv_O0g"));
    assert_eq!(
        posture.interpreter.as_deref(),
        Some("/lib64/ld-linux-x86-64.so.2")
    );
    assert_eq!(posture.nx, Some(true));
    assert_eq!(posture.relro, Some(Relro::Full));
    assert_eq!(posture.statically_linked, Some(false));
}

#[test]
fn a_static_executable_has_no_interpreter_and_no_relro() {
    let posture = posture(include_bytes!("../../../tests/fixtures/syscalls_static_O2"));
    assert_eq!(posture.interpreter, None);
    assert_eq!(posture.relro, Some(Relro::No));
    assert_eq!(posture.statically_linked, Some(true));
}

/// A shared object with `PT_DYNAMIC`, no interpreter, and no `DT_NEEDED`, `DT_SONAME` or `DF_1_PIE`:
/// nothing states whether only its own start-up builds it.
#[test]
fn a_shared_object_stating_no_dependency_states_no_static_answer() {
    let posture = posture(include_bytes!("../../../tests/fixtures/arm_plt_lld_be8.so"));
    assert_eq!(posture.interpreter, None);
    assert_eq!(posture.relro, Some(Relro::Partial));
    assert_eq!(posture.statically_linked, None);
}

/// Mach-O and PE state none of it in these terms: nothing is claimed.
#[test]
fn a_format_without_program_headers_states_no_posture() {
    let posture = posture(include_bytes!("../../../tests/fixtures/manual_limits_O0"));
    assert_eq!(posture, Posture::default());
}

/// gABI chapter 5, "Base Address": an `ET_EXEC` runs at its file's addresses, an `ET_DYN` at one
/// base; a relocatable object and a Mach-O state neither.
#[test]
fn each_header_states_where_the_loader_places_the_image() {
    let load = |bytes: &[u8]| posture(bytes).load;
    let fixtures = [
        (
            &include_bytes!("../../../tests/fixtures/syscalls_static_O2")[..],
            LoadBase::Linked,
        ),
        (
            include_bytes!("../../../tests/fixtures/rv_O0g"),
            LoadBase::Slid,
        ),
        (
            include_bytes!("../../../tests/fixtures/arm_plt_lld_be8.so"),
            LoadBase::Slid,
        ),
        (
            include_bytes!("../../../tests/fixtures/x86_64_common_code.o"),
            LoadBase::Unstated,
        ),
        (
            include_bytes!("../../../tests/fixtures/manual_limits_O0"),
            LoadBase::Unstated,
        ),
        (DYNAMIC_EXECUTABLE, LoadBase::Linked),
    ];
    for (index, (bytes, expected)) in fixtures.into_iter().enumerate() {
        assert_eq!(load(bytes), expected, "fixture {index}");
    }
}

/// A dynamic `ET_EXEC`: `PT_DYNAMIC` at 0x2e08, its `DT_DEBUG` entry (value 0) at 0x2ec8.
const DYNAMIC_EXECUTABLE: &[u8] =
    include_bytes!("../../../tests/coverage/pinned/branchy_gcc_x64_O0");

/// `DYNAMIC_EXECUTABLE` with its `DT_DEBUG` entry restated as `(tag, value)`.
fn restated(tag: i64, value: u64) -> Vec<u8> {
    let mut bytes = DYNAMIC_EXECUTABLE.to_vec();
    assert_eq!(bytes[0x2ec8..0x2ed0], 21i64.to_le_bytes(), "DT_DEBUG moved");
    bytes[0x2ec8..0x2ed0].copy_from_slice(&tag.to_le_bytes());
    bytes[0x2ed0..0x2ed8].copy_from_slice(&value.to_le_bytes());
    bytes
}

/// gABI `DT_TEXTREL` and `DF_TEXTREL`: "one or more relocation entries might request modifications
/// to a non-writable segment", so the loader may write the text and its addresses are not proven.
#[test]
fn an_executable_stating_text_relocations_states_no_load_base() {
    assert_eq!(posture(&restated(22, 0)).load, LoadBase::Unstated); // DT_TEXTREL
    assert_eq!(posture(&restated(30, 4)).load, LoadBase::Unstated); // DT_FLAGS, DF_TEXTREL
    assert_eq!(posture(&restated(30, 8)).load, LoadBase::Linked); // DT_FLAGS, DF_BIND_NOW
}

/// An `ET_EXEC` whose `PT_DYNAMIC` runs past the file states nothing about text relocations.
#[test]
fn an_executable_whose_dynamic_section_is_unreadable_states_no_load_base() {
    let mut bytes = DYNAMIC_EXECUTABLE.to_vec();
    let word = |bytes: &[u8], at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
    let (table, size) = (word(&bytes, 0x20) as usize, usize::from(bytes[0x36]));
    let header = (0..usize::from(bytes[0x38]))
        .map(|index| table + index * size)
        .find(|at| bytes[*at..*at + 4] == 2u32.to_le_bytes())
        .expect("a PT_DYNAMIC");
    let past = bytes.len() as u64 + 1;
    bytes[header + 8..header + 16].copy_from_slice(&past.to_le_bytes());
    let image = Image::parse(bytes).expect("the header past the file still parses");
    assert_eq!(image.container().posture.load, LoadBase::Unstated);
}

/// Each program header of `rv_O0g` with its offset and size set to `value`: a path and a dynamic
/// section that run past the file (D18). The posture reads to the bytes held and claims no more.
#[test]
fn a_header_stating_bytes_past_the_file_reads_only_the_bytes_the_file_holds() {
    let whole = include_bytes!("../../../tests/fixtures/rv_O0g");
    let word = |at: usize| u64::from_le_bytes(whole[at..at + 8].try_into().unwrap()) as usize;
    let (table, size, count) = (
        word(0x20),
        usize::from(u16::from_le_bytes([whole[0x36], whole[0x37]])),
        usize::from(u16::from_le_bytes([whole[0x38], whole[0x39]])),
    );
    for value in [u64::MAX, u64::MAX - 7, 1 << 40, whole.len() as u64 + 1] {
        for header in 0..count {
            let mut bytes = whole.to_vec();
            let at = table + header * size;
            // `p_offset` and `p_filesz` of an ELF64 header.
            bytes[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
            bytes[at + 32..at + 40].copy_from_slice(&value.to_le_bytes());
            if let Ok(image) = Image::parse(bytes) {
                let posture = &image.container().posture;
                assert!(posture.interpreter.is_some() || posture.statically_linked != Some(false));
            }
        }
    }
}

const DT_NEEDED: u64 = 1;
const DT_SONAME: u64 = 14;
const DT_DEBUG: u64 = 21;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
const DF_1_PIE: u64 = 0x0800_0000;

/// An `ET_DYN` with one `PT_LOAD` and a `PT_DYNAMIC` holding `tags`, no `PT_INTERP` and no section.
fn dynamic_image(tags: &[(u64, u64)]) -> Vec<u8> {
    let mut out = vec![0u8; 0x200];
    let mut at = 0x100;
    for (tag, value) in tags.iter().chain([&(0, 0)]) {
        out[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        out[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
        at += 16;
    }
    let dynamic_size = (at - 0x100) as u64;
    let mut header = Vec::new();
    header.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    header.extend_from_slice(&[0u8; 8]);
    header.extend_from_slice(&3u16.to_le_bytes()); // ET_DYN
    header.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    header.extend_from_slice(&1u32.to_le_bytes());
    header.extend_from_slice(&0x1f0u64.to_le_bytes()); // e_entry
    header.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    header.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&64u16.to_le_bytes());
    header.extend_from_slice(&56u16.to_le_bytes());
    header.extend_from_slice(&2u16.to_le_bytes()); // e_phnum
    header.extend_from_slice(&[0u8; 6]); // e_shentsize, e_shnum, e_shstrndx
    out[..64].copy_from_slice(&header);
    let mut program = |at: usize, kind: u32, flags: u32, offset: u64, size: u64| {
        let mut entry = Vec::new();
        entry.extend_from_slice(&kind.to_le_bytes());
        entry.extend_from_slice(&flags.to_le_bytes());
        entry.extend_from_slice(&offset.to_le_bytes());
        entry.extend_from_slice(&offset.to_le_bytes());
        entry.extend_from_slice(&offset.to_le_bytes());
        entry.extend_from_slice(&size.to_le_bytes());
        entry.extend_from_slice(&size.to_le_bytes());
        entry.extend_from_slice(&8u64.to_le_bytes());
        out[at..at + 56].copy_from_slice(&entry);
    };
    program(64, 1, 7, 0, 0x200); // PT_LOAD
    program(120, 2, 6, 0x100, dynamic_size); // PT_DYNAMIC
    out
}

/// A static PIE (rust_nonnull_x86_64's shape): `PT_DYNAMIC` for its own relative records, no
/// interpreter, no `DT_NEEDED`, and `DF_1_PIE` (binutils `elf/common.h` 0x08000000): only its
/// start-up builds it. Without the flag (`rust_nonnull_nopie`) nothing states it either way;
/// `DT_NEEDED` or `DT_SONAME` states another image's loader.
#[test]
fn static_is_what_the_interpreter_and_the_dynamic_table_state() {
    let stated = |tags: &[(u64, u64)]| posture(&dynamic_image(tags)).statically_linked;
    assert_eq!(stated(&[(DT_FLAGS_1, DF_1_PIE)]), Some(true));
    assert_eq!(stated(&[(DT_DEBUG, 0)]), None);
    assert_eq!(stated(&[(DT_FLAGS_1, 0)]), None);
    assert_eq!(stated(&[(DT_SONAME, 1)]), Some(false));
    assert_eq!(
        stated(&[(DT_FLAGS_1, DF_1_PIE), (DT_NEEDED, 1)]),
        Some(false)
    );
}
