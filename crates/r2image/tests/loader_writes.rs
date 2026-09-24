//! What the loader writes, each expectation as the platform's own tool states it: `dyld_info -fixups`, or the dynamic relocations and psABI-reserved words.

/// Each written range, as its first byte and the byte past its last.
fn writes(bytes: &[u8]) -> Vec<(u64, u64)> {
    let image = r2image::Image::parse(bytes.to_vec()).expect("the fixture parses");
    let ranges = image.loader_writes().iter();
    ranges.map(|range| (range.start, range.end)).collect()
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
