//! A relocatable object states no addresses, so the reader places its sections.
//!
//! Every section of an ELF object carries `sh_addr = 0`, which means unplaced
//! rather than "at zero". Reading that as an address put every section at the
//! same place, so a read answered from whichever came first and disassembling
//! such a file produced nothing. The fixture is written by `data/relocatable.py`.

const BASE: u64 = 0x0800_0000;

fn image() -> r2image::Image {
    let bytes = include_bytes!("data/relocatable.elf").to_vec();
    r2image::Image::parse(bytes).expect("a relocatable elf fixture")
}

#[test]
fn each_unplaced_section_is_placed_at_its_own_file_offset() {
    let image = image();
    let placed = |name: &str| {
        image
            .sections()
            .iter()
            .find(|section| section.name == name)
            .map(|section| section.vaddr)
    };
    assert_eq!(placed(".text"), Some(BASE + 0x40));
    assert_eq!(placed(".data"), Some(BASE + 0x48));
}

#[test]
fn the_placed_bytes_are_the_bytes_of_that_section() {
    let image = image();
    let text = image.read(BASE + 0x40, 4).expect("the code is mapped");
    assert_eq!(&*text, &[0x48, 0x31, 0xc0, 0xc3]);
    let data = image.read(BASE + 0x48, 4).expect("the data is mapped");
    assert_eq!(&*data, &42u32.to_le_bytes());
}

/// A symbol's `st_value` is an offset into its section, not an address, and an
/// untyped symbol is defined as surely as a typed one: every NASM label is
/// `STT_NOTYPE`, and a binary made of them listed no symbols at all.
#[test]
fn a_symbol_moves_with_its_section_whatever_its_type() {
    let image = image();
    let at = |name: &str| {
        image
            .symbols()
            .iter()
            .find(|symbol| symbol.name == name)
            .map(|symbol| (symbol.vaddr, symbol.defined))
    };
    assert_eq!(at("f"), Some((BASE + 0x40, true)));
    assert_eq!(at("label"), Some((BASE + 0x48, true)));
}
