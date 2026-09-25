//! Which sections hold instructions, each as the container's own flags state it: `otool -l` for a Mach-O, `readelf -S` for an ELF.

/// Whether each named section is code, in the order asked.
fn code(bytes: &[u8], names: &[&str]) -> Vec<(String, bool)> {
    let image = r2image::Image::parse(bytes.to_vec()).expect("the fixture parses");
    names
        .iter()
        .map(|name| {
            let section = image
                .sections()
                .iter()
                .find(|section| section.name == *name);
            let section = section.unwrap_or_else(|| panic!("{name} is a section"));
            (section.name.clone(), section.is_code())
        })
        .collect()
}

/// `__stubs` carries `S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS` beside `S_SYMBOL_STUBS` (flags 0x80000408), whatever its name says.
#[test]
fn a_mach_o_section_is_code_where_its_attributes_state_instructions() {
    let limits = include_bytes!("../../../tests/fixtures/manual_limits_O0");
    let stated = [
        ("__text", true),
        ("__stubs", true),
        ("__cstring", false),
        ("__unwind_info", false),
        ("__got", false),
        ("__const", false),
        ("__common", false),
    ];
    let names = stated.map(|(name, _)| name);
    let expected = stated.map(|(name, code)| (name.to_owned(), code));
    assert_eq!(code(limits, &names), expected);
}

/// An ELF states it with `SHF_EXECINSTR`, which the linkage stubs in `.plt` and `.plt.sec` carry too.
#[test]
fn an_elf_section_is_code_where_it_is_executable() {
    let hashes = include_bytes!("../../../tests/coverage/pinned/hashes_gcc_x64_O2");
    let stated = [
        (".init", true),
        (".plt", true),
        (".plt.sec", true),
        (".text", true),
        (".fini", true),
        (".rodata", false),
        (".data", false),
        (".got", false),
    ];
    let names = stated.map(|(name, _)| name);
    let expected = stated.map(|(name, code)| (name.to_owned(), code));
    assert_eq!(code(hashes, &names), expected);
}

/// What each named section holds, in the order asked.
fn roles(bytes: &[u8], names: &[&str]) -> Vec<(String, r2image::SectionRole)> {
    let image = r2image::Image::parse(bytes.to_vec()).expect("the fixture parses");
    names
        .iter()
        .map(|name| {
            let section = image
                .sections()
                .iter()
                .find(|section| section.name == *name);
            let section = section.unwrap_or_else(|| panic!("{name} is a section"));
            (section.name.clone(), section.role)
        })
        .collect()
}

/// `readelf -lSW rv_O0g`: `PT_INTERP` covers `.interp`, `PT_GNU_EH_FRAME`
/// covers `.eh_frame_hdr`, whose `eh_frame_ptr` names `.eh_frame`; the
/// loader's own tables state their types. None of them is the program's
/// data, so none is where a string of the program's can be.
#[test]
fn an_elf_section_holds_what_its_type_flags_and_program_headers_state() {
    use r2image::SectionRole as R;
    let rv = include_bytes!("../../../tests/fixtures/rv_O0g");
    let stated = [
        (".interp", R::LoaderMetadata),
        (".note.gnu.build-id", R::LoaderMetadata),
        (".gnu.hash", R::LoaderMetadata),
        (".dynsym", R::LoaderMetadata),
        (".dynstr", R::LoaderMetadata),
        (".gnu.version", R::LoaderMetadata),
        (".rela.dyn", R::LoaderMetadata),
        (".text", R::Code),
        (".rodata", R::ReadOnlyData),
        (".eh_frame_hdr", R::Unwind),
        (".eh_frame", R::Unwind),
        (".init_array", R::Data),
        (".dynamic", R::LoaderMetadata),
        (".data", R::Data),
        (".bss", R::ZeroFill),
        (".comment", R::Other),
    ];
    let names = stated.map(|(name, _)| name);
    let expected = stated.map(|(name, role)| (name.to_owned(), role));
    assert_eq!(roles(rv, &names), expected);
    let image = r2image::Image::parse(rv.to_vec()).expect("the fixture parses");
    let data: Vec<&str> = image
        .sections()
        .iter()
        .filter(|section| section.holds_static_data())
        .map(|section| section.name.as_str())
        .collect();
    assert_eq!(
        data,
        [
            ".rodata",
            ".init_array",
            ".fini_array",
            ".got",
            ".data",
            ".bss"
        ]
    );
}

/// `otool -l manual_limits_O2`: `__cstring` is `S_CSTRING_LITERALS`, and
/// `__unwind_info` is where the runtime looks for the unwinder's tables.
#[test]
fn a_mach_o_section_holds_what_its_type_and_segment_state() {
    use r2image::SectionRole as R;
    let limits = include_bytes!("../../../tests/fixtures/manual_limits_O2");
    let stated = [
        ("__text", R::Code),
        ("__cstring", R::Strings),
        ("__unwind_info", R::Unwind),
        ("__const", R::ReadOnlyData),
    ];
    let names = stated.map(|(name, _)| name);
    let expected = stated.map(|(name, role)| (name.to_owned(), role));
    assert_eq!(roles(limits, &names), expected);
}
