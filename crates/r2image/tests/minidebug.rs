//! D572: the symbols of GDB's MiniDebugInfo, the ELF an xz `.gnu_debugdata` section holds, read
//! whole under a refusing budget (doc/adr-minidebuginfo.md; tests/fixtures/README.md gives the
//! recipe).

use r2image::{Image, MiniDebugRefusal, SymbolKind};

fn fixture() -> Vec<u8> {
    let path = format!(
        "{}/../../tests/fixtures/minidebug_gcc_x64_O2",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).expect("a committed fixture")
}

/// The file offset of `.gnu_debugdata`'s bytes and of its `sh_size` field, read from the ELF64
/// section headers.
fn debugdata(elf: &[u8]) -> (usize, usize) {
    let word = |at: usize, width: usize| {
        let mut bytes = [0u8; 8];
        bytes[..width].copy_from_slice(&elf[at..at + width]);
        u64::from_le_bytes(bytes) as usize
    };
    let (table, entry, count, names) = (word(0x28, 8), word(0x3a, 2), word(0x3c, 2), word(0x3e, 2));
    let names = word(table + names * entry + 0x18, 8);
    (0..count)
        .map(|index| table + index * entry)
        .find(|header| {
            let name = names + word(*header, 4);
            elf[name..].starts_with(b".gnu_debugdata\0")
        })
        .map(|header| (word(header + 0x18, 8), header + 0x20))
        .expect("the fixture holds .gnu_debugdata")
}

/// Each unit's static `helper` is no `.dynsym` name and the stripped file has no `.symtab`: only
/// the MiniDebugInfo states them, at the places and sizes `readelf -sW` reads in the decoded
/// `.gnu_debugdata` (tests/fixtures/README.md).
#[test]
fn a_local_function_only_minidebuginfo_names_is_listed_with_its_place_and_size() {
    let image = Image::parse(fixture()).expect("an elf");
    assert_eq!(image.minidebug_refusal(), None);
    let stated = (image.symbols().iter())
        .filter(|symbol| symbol.origin.minidebug.is_some())
        .map(|symbol| (&*symbol.name, symbol.vaddr, symbol.size, symbol.kind))
        .collect::<Vec<_>>();
    for helper in [("helper", 0x11c0, 4), ("helper", 0x11e0, 62)] {
        let (name, vaddr, size) = helper;
        assert!(
            stated.contains(&(name, vaddr, size, SymbolKind::Function)),
            "{stated:?}"
        );
    }
    assert!(stated.contains(&("main", 0x1060, 101, SymbolKind::Function)));
}

#[test]
fn a_stream_cut_short_is_refused_whole() {
    let mut elf = fixture();
    let (_, size) = debugdata(&elf);
    let cut = u64::from_le_bytes(elf[size..size + 8].try_into().expect("8 bytes")) / 2;
    elf[size..size + 8].copy_from_slice(&cut.to_le_bytes());
    let image = Image::parse(elf).expect("an elf");
    assert_eq!(
        image.minidebug_refusal(),
        Some(&MiniDebugRefusal::Container(
            "no stream footer where the section ends"
        ))
    );
    assert!(
        image
            .symbols()
            .iter()
            .all(|symbol| symbol.origin.minidebug.is_none())
    );
}

/// A stream whose index states 1 GiB is refused from its footer and index, before any block.
#[test]
fn an_index_over_the_budget_is_refused_before_decoding() {
    let mut elf = fixture();
    let (at, size) = debugdata(&elf);
    // A stream header, an index of one record of 1 GiB, a footer: no block to decode at all.
    let index = [0x00, 0x01, 0x40, 0x80, 0x80, 0x80, 0x80, 0x04, 0, 0, 0, 0];
    let mut stream = vec![0xfd, b'7', b'z', b'X', b'Z', 0, 0, 1, 0, 0, 0, 0];
    stream.extend(index);
    stream.extend([0, 0, 0, 0, 2, 0, 0, 0, 0, 1, b'Y', b'Z']);
    elf[at..at + stream.len()].copy_from_slice(&stream);
    elf[size..size + 8].copy_from_slice(&(stream.len() as u64).to_le_bytes());
    let image = Image::parse(elf).expect("an elf");
    assert_eq!(
        image.minidebug_refusal(),
        Some(&MiniDebugRefusal::OverBudget { stated: 1 << 30 })
    );
}
