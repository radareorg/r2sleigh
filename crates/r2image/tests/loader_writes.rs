//! What the loader writes, each expectation as the platform's own tool states it: `dyld_info -fixups`, or the dynamic relocations and psABI-reserved words.

/// Each written range, as its first byte and the byte past its last.
fn writes(bytes: &[u8]) -> Vec<(u64, u64)> {
    let image = r2image::Image::parse(bytes.to_vec()).expect("the fixture parses");
    let ranges = image.container().written_ranges();
    ranges
        .iter()
        .map(|range| (range.start, range.end))
        .collect()
}

/// Three chained rebases in `__const`, whose file words hold an encoded target and a link, not a pointer.
#[test]
fn a_chained_fixup_is_a_write_whatever_its_file_word_says() {
    let table = include_bytes!("../../../tests/fixtures/code_pointer_table_O0");
    assert_eq!(writes(table), [(0x1_0000_4000, 0x1_0000_4018)]);
    // A bind in `__got` and two rebases in `__const`, and nothing between them.
    let limits = include_bytes!("../../../tests/fixtures/manual_limits_O0");
    assert_eq!(
        writes(limits),
        [
            (0x1_0000_4000, 0x1_0000_4008),
            (0x1_0000_4020, 0x1_0000_4028),
            (0x1_0000_4048, 0x1_0000_4050),
        ]
    );
}

/// Two `GLOB_DAT` slots, then the link map and resolver words no relocation names, then one `JUMP_SLOT`.
#[test]
fn an_elf_writes_its_relocated_slots_and_the_table_words_its_abi_reserves() {
    let hashes = include_bytes!("../../../tests/coverage/pinned/hashes_gcc_x64_O2");
    assert_eq!(
        writes(hashes),
        [(0x40_3fd8, 0x40_3fe8), (0x40_3ff0, 0x40_4008)]
    );
    // A static executable with no relocations leaves every byte as the file holds it.
    let plain = include_bytes!("data/dwarf_prototypes.elf");
    assert_eq!(writes(plain), []);
}

/// What the loader writes at `place`, as the container states it.
fn at(image: &r2image::Image, place: u64) -> Option<r2image::WriteKind> {
    let write = image.container().loader_write_at(place)?;
    (write.place == place).then(|| write.kind.clone())
}

#[test]
fn a_relative_word_holds_its_addend_however_high_the_image_is_linked() {
    // `readelf -r`: 0x14018 RELATIVE 0x14010 and 0x14020 RELATIVE 0x14014,
    // in a PIE whose first segment is linked at 0x10000. The load bias is
    // what moves them; in link coordinates they are the addends, and adding
    // where the first byte is linked would put them past the image.
    let pie =
        r2image::Image::parse(include_bytes!("data/loader_values_pie_at_0x10000.elf").to_vec())
            .expect("the fixture parses");
    assert_eq!(
        at(&pie, 0x1_4018),
        Some(r2image::WriteKind::Relative(0x1_4010))
    );
    assert_eq!(
        at(&pie, 0x1_4020),
        Some(r2image::WriteKind::Relative(0x1_4014))
    );
    assert_eq!(
        at(&pie, 0x1_3fd8),
        Some(r2image::WriteKind::Import {
            symbol: "__libc_start_main".to_owned()
        })
    );
}

#[test]
fn a_librarys_default_visibility_definition_is_its_own_only_until_another_image_interposes() {
    // `readelf -r loader_values.so`: R_X86_64_64 against `shared_global`,
    // defined here at 0x4014 with default visibility, so an executable or a
    // library ahead of this one in the lookup scope may replace it.
    let library = r2image::Image::parse(include_bytes!("data/loader_values.so").to_vec())
        .expect("the fixture parses");
    assert_eq!(
        at(&library, 0x4020),
        Some(r2image::WriteKind::Preemptible {
            symbol: "shared_global".to_owned(),
            default: 0x4014
        })
    );
    // The static one the linker made relative: nothing can replace it.
    assert_eq!(
        at(&library, 0x4018),
        Some(r2image::WriteKind::Relative(0x4010))
    );
    // The words the psABI reserves are written with no value stated.
    let reserved = library
        .loader_writes()
        .iter()
        .filter(|write| write.kind == r2image::WriteKind::Unknown)
        .count();
    assert!(reserved > 0);
}

#[test]
fn a_chained_rebase_states_its_target_and_a_bind_its_import() {
    // `dyld_info -fixups manual_limits_O0`: `__got` binds `_memcpy`, which
    // is the C identifier `memcpy`, and `__const` holds two rebases to
    // strings in `__cstring`.
    let limits =
        r2image::Image::parse(include_bytes!("../../../tests/fixtures/manual_limits_O0").to_vec())
            .expect("the fixture parses");
    assert_eq!(
        at(&limits, 0x1_0000_4000),
        Some(r2image::WriteKind::Import {
            symbol: "memcpy".to_owned()
        })
    );
    assert_eq!(
        at(&limits, 0x1_0000_4020),
        Some(r2image::WriteKind::Relative(0x1_0000_0fe4))
    );
}

#[test]
fn what_the_loader_seals_after_it_is_done_is_stated_beside_what_it_never_lets_the_program_write() {
    // `readelf -l rv_O0g`: GNU_RELRO covers 0x3da0..0x4000 of the writable
    // segment; `.data` after it stays writable.
    let rv = r2image::Image::parse(include_bytes!("../../../tests/fixtures/rv_O0g").to_vec())
        .expect("the fixture parses");
    let container = rv.container();
    let sealed: Vec<(u64, u64)> = container
        .sealed
        .iter()
        .map(|range| (range.start, range.end))
        .collect();
    assert_eq!(sealed, [(0x3da0, 0x4000)]);
    assert!(
        container.immutable(&(0x3fc8..0x3fd0)),
        "a GOT slot is sealed"
    );
    assert!(
        container.immutable(&(0x2018..0x2038)),
        "read-only data is immutable"
    );
    assert!(
        !container.immutable(&(0x4018..0x4020)),
        "`g_msg` stays writable"
    );
    assert!(
        !container.immutable(&(0x3ff8..0x4008)),
        "a range leaving the seal is not"
    );
    // `__DATA_CONST` of the Mach-O fixture is mapped writable for dyld and flagged `SG_READ_ONLY`.
    let table = r2image::Image::parse(
        include_bytes!("../../../tests/fixtures/code_pointer_table_O0").to_vec(),
    )
    .expect("the fixture parses");
    assert!(table.container().immutable(&(0x1_0000_4000..0x1_0000_4018)));
}
