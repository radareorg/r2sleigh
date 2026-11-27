//! A relocatable object states, record by record, what a static link writes into its placed sections.
//!
//! Every field such a link fills is zero in the file. The fixture, written by
//! `data/relocated.py`, calls an import and a local function, points at its
//! data, reads a table slot and a `.bss` object, and states its frames through
//! `.rela.eh_frame`.

use r2image::{Applies, Encoding, ImportStub, WriteKind};

const BASE: u64 = 0x0800_0000;
const TEXT: u64 = BASE + 0x40;
const G: u64 = TEXT + 0x1f;
const DATA: u64 = BASE + 0x60;
/// The file is 0x598 bytes, so `.bss` is the first address past it, at its alignment.
const BSS: u64 = BASE + 0x598;
/// The common symbol follows `.bss`, at its own alignment.
const SHARED: u64 = BSS + 8;
/// The linkage begins at the page after `.bss`: the stub for `ext`, then its slot.
const STUB: u64 = BASE + 0x1000;
const SLOT: u64 = STUB + 8;

fn image() -> r2image::Image {
    let bytes = include_bytes!("data/relocated.elf").to_vec();
    r2image::Image::parse(bytes).expect("a relocatable elf fixture")
}

fn written(image: &r2image::Image, place: u64) -> (WriteKind, Encoding) {
    let write = image
        .loader_writes()
        .iter()
        .find(|write| write.place == place)
        .unwrap_or_else(|| panic!("a write at {place:#x}: {:?}", image.loader_writes()));
    (write.kind.clone(), write.encoding)
}

#[test]
fn every_record_is_stated_at_its_placed_section_with_its_symbol_and_typed_kind() {
    let image = image();
    let records: Vec<(u64, Applies, Encoding, Option<i64>, &str)> = image
        .relocations()
        .iter()
        .map(|record| {
            let symbol = record.symbol.as_deref().map_or("", |symbol| &*symbol.name);
            (
                record.vaddr,
                record.applies,
                record.encoding,
                record.addend,
                symbol,
            )
        })
        .collect();
    use Applies::*;
    use Encoding::*;
    assert_eq!(
        records,
        [
            (TEXT + 0x01, PltRelative, FromPlace, Some(-4), "ext"),
            (TEXT + 0x06, PltRelative, FromPlace, Some(-4), "g"),
            (TEXT + 0x0d, PcRelative, FromPlace, Some(4), ".data"),
            (TEXT + 0x14, GotRelative, FromPlace, Some(-4), "ext"),
            (TEXT + 0x1a, PcRelative, FromPlace, Some(-4), "counter"),
            (DATA, SymbolPlusAddend, Word, Some(0), "g"),
            (BASE + 0x90, PcRelative, FromPlace, Some(0), ".text"),
            (BASE + 0xa4, PcRelative, FromPlace, Some(0x1f), ".text"),
            (BASE + 0xb8, PcRelative, FromPlace, Some(0), "ext"),
        ]
    );
    let ext = image.relocations()[0].symbol.as_deref().expect("a symbol");
    assert_eq!(ext.defined, None, "an undefined symbol is an import");
}

/// A field holding the target less its place is written, but it is no pointer: no data reader takes it as an address.
#[test]
fn a_pc_relative_field_states_where_it_resolves_and_no_word_value() {
    let image = image();
    let call = image
        .loader_writes()
        .iter()
        .find(|write| write.place == TEXT + 0x06)
        .expect("the call's field is written");
    assert_eq!(call.kind, WriteKind::Absolute(G - 4));
    assert_eq!(call.encoding, Encoding::FromPlace);
    assert_eq!(call.value(), None);
    assert_eq!(call.stated_address(), None);
    assert_eq!(call.target(), Some(G - 4));
    // The pointer in `.data` is a word, and its value is `g`.
    let word = image
        .container()
        .loader_write_at(DATA)
        .expect("the data word is written");
    assert_eq!(word.value(), Some(G));
}

/// A static link sends a call to an import through a stub and a table read through a slot; the reader places both past every section.
#[test]
fn an_import_gets_a_stub_and_a_slot_in_the_linkage() {
    let image = image();
    assert_eq!(
        image.import_stubs(),
        [ImportStub {
            vaddr: STUB,
            size: 8,
            symbol: "ext".to_owned(),
        }]
    );
    let (call, _) = written(&image, TEXT + 0x01);
    assert_eq!(call, WriteKind::Absolute(STUB - 4));
    let (read, _) = written(&image, TEXT + 0x14);
    assert_eq!(read, WriteKind::Absolute(SLOT - 4));
    let (slot, encoding) = written(&image, SLOT);
    assert_eq!(
        (slot, encoding),
        (
            WriteKind::Import {
                symbol: "ext".to_owned(),
                library: None
            },
            Encoding::Word
        )
    );
    assert_eq!(
        image.container().import_slots().collect::<Vec<_>>(),
        [(SLOT, "ext")]
    );
}

/// `.bss` holds no file bytes, so it is placed past the file rather than on top of the header.
#[test]
fn an_unbacked_section_is_placed_past_the_file_and_its_objects_move_with_it() {
    let image = image();
    let bss = image
        .sections()
        .iter()
        .find(|section| section.name == ".bss")
        .expect("a .bss");
    assert_eq!(bss.vaddr, BSS);
    let counter = image
        .symbols()
        .iter()
        .find(|symbol| &*symbol.name == "counter")
        .expect("counter");
    assert_eq!(counter.vaddr, BSS);
    let (read, _) = written(&image, TEXT + 0x1a);
    assert_eq!(read, WriteKind::Absolute(BSS - 4));
    // A common symbol's value is its alignment; the reader allocates it as a link would.
    let shared = image
        .symbols()
        .iter()
        .find(|symbol| &*symbol.name == "shared")
        .expect("shared");
    assert_eq!((shared.vaddr, shared.defined), (SHARED, true));
    assert_eq!(SHARED % 16, 0);
}

/// A section sized past the address space is refused, not placed by a wrapping sum (D18).
#[test]
fn an_object_whose_sections_overrun_the_address_space_is_refused() {
    let mut bytes = include_bytes!("data/relocated.elf").to_vec();
    let word = |at: usize, n: usize| {
        bytes[at..at + n]
            .iter()
            .rev()
            .fold(0, |v, b| v << 8 | *b as usize)
    };
    let (table, count) = (word(0x28, 8), word(0x3c, 2));
    // `.bss`, the one `SHT_NOBITS` section; its `sh_size` is at +0x20 in its 64-byte header.
    let bss = (0..count)
        .map(|i| table + i * 64)
        .find(|at| word(at + 4, 4) == 8);
    let size = bss.expect("the fixture has a .bss") + 0x20;
    bytes[size..size + 8].copy_from_slice(&(u64::MAX - 0x10).to_le_bytes());
    let refused = r2image::Image::parse(bytes).err();
    assert!(
        matches!(refused, Some(r2image::ImageError::Unplaceable)),
        "{refused:?}"
    );
}

/// Each FDE starts where the record at its `pc_begin` resolves; one resolving to an import is refused, never a frame at a raw offset.
#[test]
fn frames_start_where_their_relocations_resolve_and_an_unresolved_one_is_refused() {
    let image = image();
    let unwind = &image.container().unwind;
    let frames: Vec<(u64, u64)> = unwind
        .frames()
        .map(|frame| (frame.start, frame.end))
        .collect();
    assert_eq!(frames, [(TEXT, TEXT + 0x1f), (G, G + 1)]);
    let saves = unwind.at(TEXT).map(|frame| frame.saves.get(&16).copied());
    assert_eq!(
        saves,
        Some(Some(0)),
        "the return address at the entry stack pointer"
    );
}

/// An AArch64 GOT read of `S + A` goes through the slot GDAT(S+A), which holds `S + A`, and no addend moves the field off it.
#[test]
fn an_aarch64_got_read_of_a_symbol_plus_an_addend_has_its_own_slot() {
    let bytes = include_bytes!("data/aarch64_got_addend.elf").to_vec();
    let image = r2image::Image::parse(bytes).expect("an aarch64 relocatable fixture");
    let gdef = BASE + 0x5c;
    let slot = |field: u64| match written(&image, field).0 {
        WriteKind::Absolute(slot) => slot,
        other => panic!("the field at {field:#x} states {other:?}"),
    };
    let (plus, plain, import) = (slot(TEXT + 0x04), slot(TEXT + 0x0c), slot(TEXT + 0x14));
    assert_eq!(slot(TEXT), plus, "the page and the offset name one slot");
    assert_eq!(written(&image, plus).0, WriteKind::Absolute(gdef + 8));
    assert_eq!(written(&image, plain).0, WriteKind::Absolute(gdef));
    // An import plus an addend has no value the object states, and it is no import's slot.
    assert_eq!(written(&image, import).0, WriteKind::Unknown);
    assert!(image.container().import_slots().next().is_none());
}
