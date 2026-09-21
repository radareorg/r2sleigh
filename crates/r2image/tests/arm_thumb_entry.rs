//! On ARM the low bit of an address selects Thumb and is not part of it.
//!
//! A stripped ARM binary has no symbol at its entry, so `e_entry`'s low bit is
//! the only thing that says the entry is Thumb. Losing it decodes the entry as
//! ARM, which produces plausible instructions that are not there: on
//! `armeb_hello_static` the standard `mov.w fp, 0` prologue came out as
//! `bleq 0x4c968`.

#[test]
fn an_odd_entry_address_says_the_entry_is_thumb() {
    let bytes = include_bytes!("data/arm_thumb_entry.elf").to_vec();
    let image = r2image::Image::parse(bytes).expect("an arm elf fixture");

    let entry = image
        .entry_points()
        .iter()
        .find(|entry| entry.kind == r2image::EntryKind::Main)
        .expect("the declared entry");
    assert_eq!(entry.vaddr & 1, 0, "the bit is not part of the address");
    assert_eq!(entry.vaddr, 0x10054);
    assert!(entry.thumb, "an odd e_entry selects Thumb");
}
