//! D570: each FDE's call-site table, read under the cited personality its CIE names
//! (tests/fixtures/README.md gives the sources, the commands and the hand decodes).

use r2image::Image;
use r2image::unwind::{LsdaRead, LsdaRefusal};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).expect("a committed fixture")
}

fn ranges(image: &Image, start: u64) -> Vec<(u64, u64, Option<u64>)> {
    let frame = image.container().unwind.at(start).expect("a frame");
    (frame.pads.iter())
        .map(|range| (range.start, range.end, range.pad))
        .collect()
}

/// `guarded` at 0x12f0: `readelf --debug-dump=frames` puts its LSDA at 0x21a0; by hand,
/// `ff 9b 21 01 14`, then records `35 05 66 03`, `9f 01 05 00 00`, `ca 01 05 de 01 00`, `84 02 05 00 00`.
#[test]
fn a_gxx_frame_states_its_call_sites_and_pads() {
    let image = Image::parse(fixture("cxx_try_catch_gcc_x64_O0")).expect("an elf");
    let unwind = &image.container().unwind;
    let frame = unwind.at(0x12f0).expect("guarded's frame");
    assert!(
        matches!(frame.lsda, LsdaRead::Read(row) if row.name == "__gxx_personality_v0"),
        "{:?}",
        frame.lsda
    );
    assert_eq!(
        ranges(&image, 0x12f0),
        [
            (0x1325, 0x132a, Some(0x1356)),
            (0x138f, 0x1394, None),
            (0x13ba, 0x13bf, Some(0x13ce)),
            (0x13f4, 0x13f9, None),
        ]
    );
    // The call to `risky` at 0x1325 is five bytes; the unwinder looks up its last.
    assert_eq!(unwind.pad_for(0x1329), Some(0x1356));
    assert_eq!(unwind.pad_for(0x1393), None);
    assert_eq!(unwind.pad_for(0x13be), Some(0x13ce));
    // `risky` (0x1273) states one pad, for its throw's cleanup.
    assert_eq!(ranges(&image, 0x1273)[0], (0x12a5, 0x12aa, Some(0x12cd)));
}

/// A C cleanup under `-fexceptions` is `__gcc_personality_v0`'s: `guarded` at 0x9e8, LSDA 0xc84.
#[test]
fn a_gcc_cleanup_frame_states_its_pad_on_aarch64() {
    let image = Image::parse(fixture("c_cleanup_gcc_aarch64_O0")).expect("an elf");
    let frame = image.container().unwind.at(0x9e8).expect("guarded's frame");
    assert!(
        matches!(frame.lsda, LsdaRead::Read(row) if row.name == "__gcc_personality_v0"),
        "{:?}",
        frame.lsda
    );
    assert_eq!(
        ranges(&image, 0x9e8),
        [(0xa24, 0xa28, Some(0xa64)), (0xa98, 0xa9c, None)]
    );
}

/// A call-site table whose stated length ends inside a record is refused, and states no pad.
#[test]
fn a_table_whose_length_cuts_a_record_is_refused() {
    let mut bytes = fixture("cxx_try_catch_gcc_x64_O0");
    // The call-site table length of `guarded`'s LSDA, 0x14, at file offset 0x21a4.
    assert_eq!(bytes[0x21a4], 0x14);
    bytes[0x21a4] = 0x13;
    let image = Image::parse(bytes).expect("an elf");
    let frame = image
        .container()
        .unwind
        .at(0x12f0)
        .expect("guarded's frame");
    assert_eq!(frame.lsda, LsdaRead::Refused(LsdaRefusal::Length));
    assert!(frame.pads.is_empty());
    assert_eq!(image.container().unwind.pad_for(0x1329), None);
}

/// The format belongs to the personality: one no cited row names states no pad, and is counted.
#[test]
fn a_personality_with_no_row_states_no_pad() {
    let mut bytes = fixture("cxx_try_catch_gcc_x64_O0");
    let name = b"__gxx_personality_v0";
    let at = (bytes.windows(name.len()))
        .position(|window| window == name)
        .expect("the import's name");
    bytes[at + name.len() - 1] = b'9';
    let image = Image::parse(bytes).expect("an elf");
    let frame = image
        .container()
        .unwind
        .at(0x12f0)
        .expect("guarded's frame");
    assert_eq!(frame.lsda, LsdaRead::PersonalityUnstated);
    assert!(frame.pads.is_empty());
}
