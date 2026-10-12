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
