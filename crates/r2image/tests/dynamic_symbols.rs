//! An ELF states its dynamic symbols through the dynamic table, whatever section headers remain:
//! `DT_SYMTAB`, `DT_STRTAB`, `DT_SYMENT`, counted by `DT_HASH` or `DT_GNU_HASH` (gABI; D542).

use r2image::{Binding, Image, SymbolKind, Visibility};

type Stated = (
    String,
    u64,
    u64,
    SymbolKind,
    bool,
    bool,
    Binding,
    Visibility,
    usize,
);

fn dynamic(bytes: &[u8]) -> Vec<Stated> {
    let image = Image::parse(bytes.to_vec()).expect("the fixture parses");
    let mut symbols: Vec<Stated> = image
        .symbols()
        .iter()
        .filter_map(|symbol| {
            Some((
                symbol.name.to_string(),
                symbol.vaddr,
                symbol.size,
                symbol.kind,
                symbol.defined,
                symbol.import,
                symbol.binding,
                symbol.visibility,
                symbol.origin.dynamic?,
            ))
        })
        .collect();
    symbols.sort_by_key(|symbol| symbol.8);
    symbols
}

/// The file with no section header: `e_shoff`, `e_shnum` and `e_shstrndx` zeroed.
fn unsectioned(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    let fields: &[(usize, usize)] = match bytes[4] {
        1 => &[(0x20, 4), (0x30, 2), (0x32, 2)],
        _ => &[(0x28, 8), (0x3c, 2), (0x3e, 2)],
    };
    for (at, width) in fields {
        bytes[*at..at + width].fill(0);
    }
    bytes
}

#[test]
fn an_image_with_no_section_header_lists_its_dynamic_symbols_through_the_gnu_hash_count() {
    let library = include_bytes!("data/loader_values.so");
    let sectioned = dynamic(library);
    let names: Vec<&str> = sectioned.iter().map(|symbol| &*symbol.0).collect();
    assert!(
        names.contains(&"get") && names.contains(&"main"),
        "{names:?}"
    );
    assert_eq!(dynamic(&unsectioned(library)), sectioned);
}

#[test]
fn an_image_with_no_section_header_lists_its_dynamic_symbols_through_the_sysv_hash_count() {
    let library = include_bytes!("../../../tests/fixtures/arm_plt_lld_be8.so");
    let sectioned = dynamic(library);
    assert_eq!(sectioned.len(), 3, "{sectioned:?}");
    let mut bytes = unsectioned(library);
    // The dynamic table's ninth entry is `DT_GNU_HASH`; as `DT_DEBUG` only `DT_HASH` counts.
    assert_eq!(bytes[0x270..0x274], [0x6f, 0xff, 0xfe, 0xf5]);
    bytes[0x270..0x274].copy_from_slice(&21u32.to_be_bytes());
    assert_eq!(dynamic(&bytes), sectioned);
    // With neither hash table nothing states the count, so no symbol is read past the table.
    assert_eq!(bytes[0x278..0x27c], [0, 0, 0, 4]);
    bytes[0x278..0x27c].copy_from_slice(&21u32.to_be_bytes());
    assert_eq!(dynamic(&bytes), []);
}
