//! An image opened from its file maps the bytes, and states what parsing a copy of them states.

#[test]
fn an_opened_image_states_what_a_copy_of_its_bytes_states() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/dwarf_graph.elf");
    let opened = r2image::Image::open(path).expect("the fixture opens");
    let copied = std::fs::read(path).expect("the fixture reads");
    let parsed = r2image::Image::parse(copied).expect("the fixture parses");
    assert_eq!(
        format!("{:?}", opened.container()),
        format!("{:?}", parsed.container())
    );
    let held = (parsed.sections().iter()).filter(|section| section.file_size > 0);
    for section in held {
        assert_eq!(
            opened.file_bytes(section.file_offset, section.file_size),
            parsed.file_bytes(section.file_offset, section.file_size),
            "{}",
            section.name
        );
    }
}

#[test]
fn an_empty_file_is_no_binary_rather_than_a_map_that_failed() {
    let path = std::env::temp_dir().join(format!("r2image-empty-{}", std::process::id()));
    std::fs::write(&path, []).expect("an empty file");
    let opened = r2image::Image::open(&path);
    std::fs::remove_file(&path).expect("the file is removed");
    assert!(matches!(opened, Err(r2image::ImageError::Parse(_))));
}

/// A fat file holding one slice: the image is the slice, and states where it begins in the file.
#[test]
fn a_fat_file_s_slice_states_where_it_begins() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/manual_limits_O2"
    );
    let thin = std::fs::read(path).expect("the fixture reads");
    const BASE: usize = 0x4000;
    let mut fat = Vec::with_capacity(BASE + thin.len());
    for word in [
        0xcafe_babe_u32,
        1,
        0x0100_000c,
        0,
        BASE as u32,
        thin.len() as u32,
        14,
    ] {
        fat.extend_from_slice(&word.to_be_bytes());
    }
    fat.resize(BASE, 0);
    fat.extend_from_slice(&thin);
    let sliced = r2image::Image::parse(fat).expect("the fat file parses");
    let alone = r2image::Image::parse(thin).expect("the slice parses");
    assert_eq!(sliced.file_base(), BASE as u64);
    assert_eq!(alone.file_base(), 0);
    assert_eq!(
        format!("{:?}", sliced.container()),
        format!("{:?}", alone.container())
    );
}
