//! The initialiser and terminator arrays an ELF image states for its loader, read through
//! `PT_DYNAMIC` where no section header remains (gABI "Dynamic Section").

use r2image::{EntryKind, Image};

const BASE: u64 = 0x40_0000;
const DT_INIT_ARRAY: u64 = 25;
const DT_INIT_ARRAYSZ: u64 = 27;
const DT_FINI_ARRAY: u64 = 26;
const DT_FINI_ARRAYSZ: u64 = 28;
const DT_PREINIT_ARRAY: u64 = 32;
const DT_PREINIT_ARRAYSZ: u64 = 33;
const DT_DEBUG: u64 = 21;

/// An `ET_EXEC` with `ret` at 0x200 to 0x230 and the arrays at 0x300 (init, two slots), 0x310 (fini),
/// 0x318 (preinit); `tags` is its dynamic table, `init_section` adds `.init_array`'s header.
fn image(tags: &[(u64, u64)], init_section: bool) -> Vec<u8> {
    let mut out = vec![0u8; 0x400];
    for code in [0x200, 0x210, 0x220, 0x230] {
        out[code] = 0xc3;
    }
    for (slot, target) in [
        (0x300, 0x200),
        (0x308, 0x210),
        (0x310, 0x220),
        (0x318, 0x230),
    ] {
        out[slot..slot + 8].copy_from_slice(&(BASE + target).to_le_bytes());
    }
    let mut at = 0x340;
    for (tag, value) in tags.iter().chain([&(0, 0)]) {
        out[at..at + 8].copy_from_slice(&tag.to_le_bytes());
        out[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
        at += 16;
    }
    let dynamic_size = (at - 0x340) as u64;
    let names = b"\0.init_array\0.shstrtab\0";
    out[0x3c0..0x3c0 + names.len()].copy_from_slice(names);
    let (shoff, shnum, shstrndx) = if init_section {
        let shoff = out.len() as u64;
        out.extend_from_slice(&[0u8; 64]); // SHT_NULL
        let mut section = |name: u32, kind: u32, flags: u64, addr: u64, offset: u64, size: u64| {
            out.extend_from_slice(&name.to_le_bytes());
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&addr.to_le_bytes());
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&[0u8; 8]); // sh_link, sh_info
            out.extend_from_slice(&8u64.to_le_bytes());
            out.extend_from_slice(&if kind == 14 { 8u64 } else { 0 }.to_le_bytes());
        };
        section(1, 14, 3, BASE + 0x300, 0x300, 16); // .init_array: SHT_INIT_ARRAY, write and alloc
        section(13, 3, 0, 0, 0x3c0, names.len() as u64); // .shstrtab
        (shoff, 3u16, 2u16)
    } else {
        (0, 0, 0)
    };
    let mut header = Vec::new();
    header.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    header.extend_from_slice(&[0u8; 8]);
    header.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    header.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    header.extend_from_slice(&1u32.to_le_bytes());
    header.extend_from_slice(&(BASE + 0x200).to_le_bytes()); // e_entry
    header.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    header.extend_from_slice(&shoff.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&64u16.to_le_bytes());
    header.extend_from_slice(&56u16.to_le_bytes());
    header.extend_from_slice(&2u16.to_le_bytes()); // e_phnum
    header.extend_from_slice(&64u16.to_le_bytes());
    header.extend_from_slice(&shnum.to_le_bytes());
    header.extend_from_slice(&shstrndx.to_le_bytes());
    out[..64].copy_from_slice(&header);
    let mut program = |at: usize, kind: u32, offset: u64, size: u64| {
        let mut entry = Vec::new();
        entry.extend_from_slice(&kind.to_le_bytes());
        entry.extend_from_slice(&7u32.to_le_bytes()); // read, write, execute
        entry.extend_from_slice(&offset.to_le_bytes());
        entry.extend_from_slice(&(BASE + offset).to_le_bytes());
        entry.extend_from_slice(&(BASE + offset).to_le_bytes());
        entry.extend_from_slice(&size.to_le_bytes());
        entry.extend_from_slice(&size.to_le_bytes());
        entry.extend_from_slice(&8u64.to_le_bytes());
        out[at..at + 56].copy_from_slice(&entry);
    };
    program(64, 1, 0, 0x400); // PT_LOAD
    program(120, 2, 0x340, dynamic_size); // PT_DYNAMIC
    out
}

fn arrays(bytes: Vec<u8>) -> Vec<(EntryKind, u64, Option<u64>)> {
    let image = Image::parse(bytes).expect("the image parses");
    let kinds = [EntryKind::Init, EntryKind::Fini, EntryKind::Preinit];
    (image.entry_points().iter())
        .filter(|entry| kinds.contains(&entry.kind))
        .map(|entry| {
            let slot = entry.stated_at.and_then(|at| at.vaddr);
            (entry.kind, entry.vaddr, slot)
        })
        .collect()
}

const ALL: [(u64, u64); 6] = [
    (DT_INIT_ARRAY, BASE + 0x300),
    (DT_INIT_ARRAYSZ, 16),
    (DT_FINI_ARRAY, BASE + 0x310),
    (DT_FINI_ARRAYSZ, 8),
    (DT_PREINIT_ARRAY, BASE + 0x318),
    (DT_PREINIT_ARRAYSZ, 8),
];

const EXPECTED: [(EntryKind, u64, Option<u64>); 4] = [
    (EntryKind::Init, BASE + 0x200, Some(BASE + 0x300)),
    (EntryKind::Init, BASE + 0x210, Some(BASE + 0x308)),
    (EntryKind::Fini, BASE + 0x220, Some(BASE + 0x310)),
    (EntryKind::Preinit, BASE + 0x230, Some(BASE + 0x318)),
];

/// x86_64-noshdr-jmpslot's shape: no section header, so only the dynamic table states the arrays.
#[test]
fn a_section_less_image_lists_the_arrays_its_dynamic_table_states() {
    assert_eq!(arrays(image(&ALL, false)), EXPECTED);
}

/// `DT_INIT_ARRAY` without `DT_INIT_ARRAYSZ` states no extent: the loader reads no slot of it.
#[test]
fn an_array_tag_without_its_size_states_nothing() {
    let mut tags = ALL;
    tags[1] = (DT_DEBUG, 0);
    assert_eq!(arrays(image(&tags, false)), EXPECTED[2..]);
}

/// A slot a section header and the dynamic table both state is one entry; the section alone states it too.
#[test]
fn a_slot_stated_by_a_section_and_the_dynamic_table_is_listed_once() {
    assert_eq!(arrays(image(&ALL, true)), EXPECTED);
    assert_eq!(arrays(image(&ALL[2..], true)), EXPECTED);
}
