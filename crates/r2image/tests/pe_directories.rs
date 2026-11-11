//! A PE image states its imports by address table slot and DLL, and its exports by name (audit M1).

/// A PE32+ image of one `.rdata` section whose load configuration states `Size` and
/// `SecurityCookie`, laid out as `pe_imports.py` lays its fixture.
fn load_config(size: u32, cookie: u64) -> Vec<u8> {
    const BASE: u64 = 0x1_4000_0000;
    let mut out = vec![0u8; 0x400];
    let put = |out: &mut Vec<u8>, at: usize, bytes: &[u8]| {
        out[at..at + bytes.len()].copy_from_slice(bytes);
    };
    put(&mut out, 0, b"MZ");
    put(&mut out, 0x3c, &0x80u32.to_le_bytes());
    put(&mut out, 0x80, b"PE\0\0");
    // COFF: x86-64, one section, a PE32+ optional header, an executable image.
    for (at, half) in [(0x84, 0x8664u16), (0x86, 1), (0x94, 0xf0), (0x96, 0x22)] {
        put(&mut out, at, &half.to_le_bytes());
    }
    let optional = 0x98;
    put(&mut out, optional, &0x20bu16.to_le_bytes());
    put(&mut out, optional + 16, &0x1000u32.to_le_bytes()); // AddressOfEntryPoint
    put(&mut out, optional + 24, &BASE.to_le_bytes());
    put(&mut out, optional + 32, &0x1000u32.to_le_bytes()); // SectionAlignment
    put(&mut out, optional + 36, &0x200u32.to_le_bytes()); // FileAlignment
    put(&mut out, optional + 56, &0x2000u32.to_le_bytes()); // SizeOfImage
    put(&mut out, optional + 60, &0x200u32.to_le_bytes()); // SizeOfHeaders
    put(&mut out, optional + 68, &3u16.to_le_bytes()); // Subsystem
    put(&mut out, optional + 108, &16u32.to_le_bytes()); // NumberOfRvaAndSizes
    // Directory 10, the load configuration, at the section's start.
    put(&mut out, optional + 112 + 10 * 8, &0x1000u32.to_le_bytes());
    put(
        &mut out,
        optional + 112 + 10 * 8 + 4,
        &0x138u32.to_le_bytes(),
    );
    let header = optional + 0xf0;
    put(&mut out, header, b".rdata\0\0");
    for (at, word) in [(8, 0x200u32), (12, 0x1000), (16, 0x200), (20, 0x200)] {
        put(&mut out, header + at, &word.to_le_bytes());
    }
    put(&mut out, header + 36, &0x4000_0040u32.to_le_bytes());
    put(&mut out, 0x200, &size.to_le_bytes());
    put(&mut out, 0x258, &cookie.to_le_bytes());
    out
}

/// The `/GS` cookie is the address the load configuration's `SecurityCookie` names (winnt.h,
/// `IMAGE_LOAD_CONFIG_DIRECTORY64`); a structure too short to hold the field names none.
#[test]
fn the_load_configuration_names_the_security_cookie() {
    let cookie = |size, at| {
        let image = r2image::Image::parse(load_config(size, at)).expect("the image parses");
        image.container().security_cookie
    };
    assert_eq!(cookie(0x138, 0x1_4000_1100), Some(0x1_4000_1100));
    assert_eq!(
        cookie(0x58, 0x1_4000_1100),
        None,
        "Size stops before the field"
    );
    assert_eq!(cookie(0x138, 0), None, "a zero field names no cookie");
}

fn fixture() -> r2image::Image {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/pe_imports_x64.dll"
    );
    r2image::Image::open(path).expect("the fixture opens")
}

#[test]
fn each_import_is_its_slot_by_dll_and_the_loader_writes_it() {
    let image = fixture();
    let imports: Vec<_> = image
        .symbols()
        .iter()
        .filter(|symbol| symbol.import)
        .collect();
    let stated: Vec<_> = imports
        .iter()
        .map(|symbol| (symbol.vaddr, &*symbol.name, symbol.library.as_deref()))
        .collect();
    assert_eq!(
        stated,
        [
            (0x1_4000_2060, "ExitProcess", Some("KERNEL32.dll")),
            // The container states only an ordinal; a name would be a guess.
            (0x1_4000_2068, "Ordinal_7", Some("KERNEL32.dll")),
        ]
    );
    let write = image
        .container()
        .loader_write_at(0x1_4000_2060)
        .expect("the slot is written");
    assert_eq!(
        write.kind,
        r2image::WriteKind::Import {
            symbol: "ExitProcess".to_owned(),
            library: Some("KERNEL32.dll".to_owned()),
        }
    );
}

/// The directory states the export's address and name, not its type: whether it begins a function
/// is discovery's to say.
#[test]
fn an_export_is_a_defined_symbol_of_this_image_with_no_stated_type() {
    let image = fixture();
    let export = image
        .symbols()
        .iter()
        .find(|symbol| &*symbol.name == "start_here")
        .expect("the export is stated");
    assert_eq!(export.vaddr, 0x1_4000_1000);
    assert!(export.defined && !export.import);
    assert_eq!(export.kind, r2image::SymbolKind::Other);
    assert_eq!(export.library.as_deref(), Some("fixture.dll"));
}

/// An unused ordinal's address slot is 0, which states no export: none lands at the image base.
#[test]
fn a_null_export_address_slot_states_no_export() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/pe_imports_x64.dll"
    );
    let mut bytes = std::fs::read(path).expect("the fixture reads");
    // `.edata` lies at RVA 0x3000, file 0x800; its zero bytes at 0x3034 hold a gapped table.
    let at = |rva: usize| rva - 0x3000 + 0x800;
    let mut put =
        |rva: usize, value: &[u8]| bytes[at(rva)..at(rva) + value.len()].copy_from_slice(value);
    put(0x3014, &2u32.to_le_bytes()); // NumberOfFunctions
    put(0x301c, &0x3034u32.to_le_bytes()); // AddressOfFunctions
    put(0x3034, &[0, 0, 0, 0, 0, 0x10, 0, 0]); // slot 0 unused, slot 1 start_here
    put(0x3030, &1u16.to_le_bytes()); // start_here's slot
    let image = r2image::Image::parse(bytes).expect("the patched fixture parses");
    let exports: Vec<_> = image
        .symbols()
        .iter()
        .filter(|symbol| symbol.defined && symbol.library.as_deref() == Some("fixture.dll"))
        .map(|symbol| (symbol.vaddr, &*symbol.name, symbol.origin.directory))
        .collect();
    assert_eq!(exports, [(0x1_4000_1000, "start_here", Some(1))]);
}

/// The name and address tables may lie before the directory; every read stays in the mapped image.
#[test]
fn an_export_name_before_the_directory_resolves() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/pe_imports_x64.dll"
    );
    let mut bytes = std::fs::read(path).expect("the fixture reads");
    let at = |rva: usize| rva - 0x3000 + 0x800;
    // Move the 40-byte directory after its tables and names, then point the data directory at it.
    let header: Vec<u8> = bytes[at(0x3000)..at(0x3028)].to_vec();
    bytes[at(0x3080)..at(0x30a8)].copy_from_slice(&header);
    bytes[at(0x3000)..at(0x3028)].fill(0);
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let entry = pe + 24 + 112;
    bytes[entry..entry + 4].copy_from_slice(&0x3080u32.to_le_bytes());
    bytes[entry + 4..entry + 8].copy_from_slice(&40u32.to_le_bytes());
    let image = r2image::Image::parse(bytes).expect("the patched fixture parses");
    let exports: Vec<_> = image
        .symbols()
        .iter()
        .filter(|symbol| symbol.defined && symbol.library.as_deref() == Some("fixture.dll"))
        .map(|symbol| (symbol.vaddr, &*symbol.name))
        .collect();
    assert_eq!(exports, [(0x1_4000_1000, "start_here")]);
}

/// A table count past the bytes the file holds states no export, not a truncated or huge one.
#[test]
fn an_export_table_past_the_file_states_no_export() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/pe_imports_x64.dll"
    );
    let mut bytes = std::fs::read(path).expect("the fixture reads");
    bytes[0x814..0x818].copy_from_slice(&u32::MAX.to_le_bytes()); // NumberOfFunctions
    let image = r2image::Image::parse(bytes).expect("the patched fixture parses");
    assert!(
        !image
            .symbols()
            .iter()
            .any(|symbol| symbol.library.as_deref() == Some("fixture.dll"))
    );
}

/// An ordinal base past 16 bits still lists the exports, each by its name where it has one.
#[test]
fn an_ordinal_base_past_sixteen_bits_lists_its_exports() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/pe_imports_x64.dll"
    );
    let mut bytes = std::fs::read(path).expect("the fixture reads");
    bytes[0x810..0x814].copy_from_slice(&0xffff_fff9u32.to_le_bytes()); // Base
    let image = r2image::Image::parse(bytes).expect("the patched fixture parses");
    let found = image
        .symbols()
        .iter()
        .any(|symbol| symbol.defined && &*symbol.name == "start_here");
    assert!(found);
}
