//! The functions an ELF dynamic table names for the loader to call itself, as `readelf -d` states
//! them: `DT_INIT` and `DT_FINI`.

use r2image::EntryKind;

/// A stripped binary keeps its dynamic table: `DT_INIT` names `.init`'s `_init`, `DT_FINI`
/// `.fini`'s `_fini`, and each is stated at its entry's value field, which holds the address.
#[test]
fn the_dynamic_table_states_the_loaders_own_hooks() {
    let bytes = include_bytes!("../../../tests/fixtures/hashes_gcc_x64_O2_stripped");
    let image = r2image::Image::parse(bytes.to_vec()).expect("the fixture parses");
    let hooks = (image.entry_points().iter())
        .filter(|entry| matches!(entry.kind, EntryKind::InitHook | EntryKind::FiniHook))
        .collect::<Vec<_>>();
    let found = hooks
        .iter()
        .map(|entry| (entry.kind, entry.vaddr))
        .collect::<Vec<_>>();
    assert_eq!(
        found,
        [
            (EntryKind::InitHook, 0x401000),
            (EntryKind::FiniHook, 0x401ba0)
        ]
    );
    for entry in hooks {
        let stated = entry.stated_at.expect("the table states it");
        let at = usize::try_from(stated.offset).expect("a file offset");
        let word = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"));
        assert_eq!(word, entry.vaddr, "{entry:?}");
    }
}

/// A PIE's fini array slot is a `RELA` record's place, and the record states the entry again in
/// its `r_addend` word: rv_O0g's `.rela.dyn` entry at `0x608` writes `0x3da8`, its addend at `0x618`.
#[test]
fn a_rela_record_states_where_its_addend_word_is() {
    let bytes = include_bytes!("../../../tests/fixtures/rv_O0g");
    let image = r2image::Image::parse(bytes.to_vec()).expect("the fixture parses");
    let fini = (image.entry_points().iter())
        .find(|entry| entry.kind == EntryKind::Fini)
        .expect("a fini array entry");
    let slot = fini
        .stated_at
        .and_then(|at| at.vaddr)
        .expect("a mapped slot");
    let record = (image.relocations().iter())
        .find(|record| record.vaddr == slot)
        .expect("a record writes the slot");
    let at = record.addend_at.expect("a RELA addend word");
    assert_eq!((at.offset, at.vaddr), (0x618, Some(0x618)));
    let word = u64::from_le_bytes(bytes[0x618..0x620].try_into().expect("eight bytes"));
    assert_eq!(word, fini.vaddr);
}
