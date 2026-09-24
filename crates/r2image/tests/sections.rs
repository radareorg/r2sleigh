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
            (section.name.clone(), section.is_code)
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
