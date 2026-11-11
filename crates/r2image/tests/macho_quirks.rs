//! What a Mach-O image states, read as dyld and the linker read it. The fixtures are written by `data/macho_quirks.py`.

fn image(bytes: &[u8]) -> r2image::Image {
    r2image::Image::parse(bytes.to_vec()).expect("a Mach-O fixture")
}

#[test]
fn an_indirect_symbol_states_no_address() {
    let image = image(include_bytes!("data/macho_indirect"));
    let named = |name: &str| image.symbols().iter().any(|symbol| &*symbol.name == name);
    assert!(named("_start"));
    assert!(
        !named("_alias"),
        "N_INDR's n_value is the index of the name it stands for"
    );
}

#[test]
fn lc_main_is_an_offset_from_the_mapped_header_and_names_main_in_its_mode() {
    use r2image::EntryKind;
    let image = image(include_bytes!("data/macho_thumb_main"));
    let entry = |kind: EntryKind| {
        (image.entry_points().iter())
            .find(|entry| entry.kind == kind)
            .map(|entry| (entry.vaddr, entry.thumb))
    };
    // __TEXT maps file offset 0 at 0x1000, so entryoff 0x1801 is Thumb code at 0x2800, not 0x1800.
    assert_eq!(entry(EntryKind::Main), Some((0x2800, true)));
    assert_eq!(entry(EntryKind::CMain), Some((0x2800, true)));
}

#[test]
fn an_object_s_sections_and_symbols_are_where_it_states_them() {
    let image = image(include_bytes!("data/macho_object"));
    assert!(!image.relocatable(), "a Mach-O object states its addresses");
    let text = (image.sections().iter())
        .find(|section| section.name == "__text")
        .expect("the fixture states __text");
    assert_eq!((text.vaddr, text.file_offset), (0, 0x100));
    assert_eq!(
        image.read(0, 1).as_deref(),
        Some(&[0xc3][..]),
        "__text is mapped at 0"
    );
    let f = (image.symbols().iter())
        .find(|symbol| &*symbol.name == "_f")
        .expect("the fixture states _f");
    assert_eq!(f.vaddr, 4);
}

#[test]
fn mach_o_states_thumb_in_n_desc_and_in_a_function_start_s_low_bit() {
    use r2image::EntryKind;
    let image = image(include_bytes!("data/macho_thumb_main"));
    let main = (image.symbols().iter())
        .find(|symbol| &*symbol.name == "_main")
        .expect("the fixture states _main");
    assert_eq!((main.vaddr, main.thumb), (0x2800, true));
    let declared = (image.entry_points().iter())
        .find(|entry| entry.kind == EntryKind::Declared)
        .map(|entry| (entry.vaddr, entry.thumb));
    assert_eq!(declared, Some((0x2800, true)));
}

#[test]
fn a_dsym_maps_only_the_section_bytes_it_holds() {
    const TEXT: u64 = 0x1_0000_0000;
    let image = image(include_bytes!("data/macho_dsym"));
    let text = (image.sections().iter())
        .find(|section| section.name == "__text")
        .expect("the fixture states __text");
    assert_eq!(text.file_size, 0, "offset 0 in a dSYM is no bytes");
    assert_eq!(
        image.read(TEXT + 0x1000, 4),
        None,
        "nothing is there, not zeros"
    );
    assert_eq!(
        image.read(TEXT, 4),
        None,
        "__TEXT's file range is not its start's"
    );
    let frame = image
        .read(TEXT + 0x1800, 4)
        .expect("__eh_frame's bytes are held");
    assert_eq!(&*frame, &[1, 2, 3, 4]);
}

/// A two-level namespace names each import's dylib by ordinal in `n_desc` (`data/macho_two_level.c`).
#[test]
fn a_two_level_import_names_its_dylib_by_ordinal() {
    let image = image(include_bytes!("data/macho_two_level"));
    let library = |name: &str| {
        (image.symbols().iter())
            .find(|symbol| symbol.import && &*symbol.name == name)
            .map(|symbol| symbol.library.as_deref().map(str::to_owned))
    };
    let named = |dylib: &str| Some(Some(dylib.to_owned()));
    assert_eq!(library("puts"), named("/usr/lib/libSystem.B.dylib"));
    assert_eq!(library("zlibVersion"), named("/usr/lib/libz.1.dylib"));
}
