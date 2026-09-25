//! Every relocation record the loader or a start-up applies, each once, as the platform's own tool lists them: `readelf -r`, or `dyld_info -fixups`.

use std::collections::BTreeSet;

use r2image::{Applies, Image};

fn image(bytes: &[u8]) -> Image {
    Image::parse(bytes.to_vec()).expect("the fixture parses")
}

/// No record is stated twice, whichever table views reached it.
fn distinct(image: &Image) -> bool {
    let records: BTreeSet<_> = image
        .relocations()
        .iter()
        .map(|relocation| relocation.record)
        .collect();
    records.len() == image.relocations().len()
}

#[test]
fn a_pie_states_its_relative_records_with_their_addends_beside_its_symbol_bindings() {
    // `readelf -r rv_O0g`: nine records in `.rela.dyn`, four of them
    // R_X86_64_RELATIVE, and four JUMP_SLOTs in `.rela.plt`. The relative ones
    // name no symbol, which is what the first reader filtered them out for.
    let rv = image(include_bytes!("../../../tests/fixtures/rv_O0g"));
    assert_eq!(rv.relocations().len(), 13);
    assert!(distinct(&rv));
    let relative: Vec<(u64, Option<i64>)> = rv
        .relocations()
        .iter()
        .filter(|relocation| relocation.applies == Applies::Relative)
        .map(|relocation| (relocation.vaddr, relocation.addend))
        .collect();
    assert_eq!(
        relative,
        [
            (0x3da0, Some(0x11a0)),
            (0x3da8, Some(0x1160)),
            (0x4008, Some(0x4008)),
            (0x4018, Some(0x2008)),
        ]
    );
    let printf = rv
        .relocations()
        .iter()
        .find(|relocation| relocation.vaddr == 0x3fc8)
        .expect("printf's slot is relocated");
    assert_eq!(printf.ntype, 7, "R_X86_64_JUMP_SLOT");
    assert_eq!(printf.applies, Applies::Symbol);
    let symbol = printf.symbol.as_ref().expect("it names printf");
    assert_eq!((symbol.name.as_str(), symbol.defined), ("printf", None));

    // The stripped fixture has three, as `readelf -r` lists them.
    let hashes = image(include_bytes!(
        "../../../tests/fixtures/hashes_gcc_x64_O2_stripped"
    ));
    let listed: Vec<(u64, u32)> = hashes
        .relocations()
        .iter()
        .map(|relocation| (relocation.vaddr, relocation.ntype))
        .collect();
    assert_eq!(listed, [(0x40_3fd8, 6), (0x40_3fe0, 6), (0x40_4000, 7)]);
}

#[test]
fn a_mach_o_stub_is_an_import_stub_and_never_a_relocation() {
    // `dyld_info -fixups manual_limits_O0`: one bind of `_memcpy` in `__got`,
    // and two rebases in `__const`; the stub in `__stubs` is code.
    let limits = image(include_bytes!("../../../tests/fixtures/manual_limits_O0"));
    assert!(distinct(&limits));
    let stubs = limits
        .sections()
        .iter()
        .find(|section| section.name == "__stubs")
        .map(|section| section.vaddr..section.vaddr + section.vsize)
        .expect("the fixture has stubs");
    assert!(
        limits
            .relocations()
            .iter()
            .all(|relocation| !stubs.contains(&relocation.vaddr)),
        "a stub is listed as a relocation"
    );
    let bound: Vec<(u64, &str)> = limits
        .relocations()
        .iter()
        .filter_map(|relocation| {
            Some((relocation.vaddr, relocation.symbol.as_ref()?.name.as_str()))
        })
        .collect();
    assert_eq!(bound, [(0x1_0000_4000, "_memcpy")]);
    let rebased: Vec<(u64, Option<i64>)> = limits
        .relocations()
        .iter()
        .filter(|relocation| relocation.applies == Applies::Relative)
        .map(|relocation| (relocation.vaddr, relocation.addend))
        .collect();
    assert_eq!(
        rebased,
        [
            (0x1_0000_4020, Some(0x1_0000_0fe4)),
            (0x1_0000_4048, Some(0x1_0000_0fe8)),
        ]
    );
    let declared: Vec<(u64, u64, &str)> = limits
        .import_stubs()
        .iter()
        .map(|stub| (stub.vaddr, stub.size, stub.symbol.as_str()))
        .collect();
    assert_eq!(declared, [(stubs.start, 12, "_memcpy")]);
}

/// A static executable whose only relocation table is `.rela.iplt`, which
/// its start-up applies and no dynamic table names; with `dynamic`, a
/// `PT_DYNAMIC` names the same table too.
fn static_iplt(dynamic: bool) -> Vec<u8> {
    const BASE: u64 = 0x40_0000;
    let names = b"\0.rela.iplt\0.shstrtab\0";
    let mut out = vec![0u8; 0x100];
    // One R_X86_64_IRELATIVE: the resolver at BASE+0x1010 fills BASE+0x2000.
    out.extend_from_slice(&(BASE + 0x2000).to_le_bytes());
    out.extend_from_slice(&37u64.to_le_bytes());
    out.extend_from_slice(&(BASE + 0x1010).to_le_bytes());
    out.resize(0x120, 0);
    for (tag, value) in [(7u64, BASE + 0x100), (8, 24), (9, 24), (0, 0)] {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.resize(0x160, 0);
    out.extend_from_slice(names);
    out.resize(0x180, 0);
    let shoff = out.len() as u64;
    let mut section = |name: u32, kind: u32, flags: u64, addr: u64, offset: u64, size: u64| {
        out.extend_from_slice(&name.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&addr.to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // sh_link: no symbol table
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&8u64.to_le_bytes());
        out.extend_from_slice(&if kind == 4 { 24u64 } else { 0 }.to_le_bytes());
    };
    section(0, 0, 0, 0, 0, 0);
    section(1, 4, 0x42, BASE + 0x100, 0x100, 24); // .rela.iplt: SHT_RELA, SHF_ALLOC|SHF_INFO_LINK
    section(12, 3, 0, 0, 0x160, names.len() as u64); // .shstrtab
    let end = out.len() as u64;

    let headers = if dynamic { 2u16 } else { 1 };
    let mut header = Vec::new();
    header.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    header.extend_from_slice(&[0u8; 8]);
    header.extend_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    header.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    header.extend_from_slice(&1u32.to_le_bytes());
    header.extend_from_slice(&(BASE + 0x1000).to_le_bytes()); // e_entry
    header.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    header.extend_from_slice(&shoff.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&64u16.to_le_bytes());
    header.extend_from_slice(&56u16.to_le_bytes());
    header.extend_from_slice(&headers.to_le_bytes());
    header.extend_from_slice(&64u16.to_le_bytes());
    header.extend_from_slice(&3u16.to_le_bytes());
    header.extend_from_slice(&2u16.to_le_bytes());
    out[..64].copy_from_slice(&header);
    let mut program = |at: usize, kind: u32, flags: u32, offset: u64, size: u64, memsz: u64| {
        let mut entry = Vec::new();
        entry.extend_from_slice(&kind.to_le_bytes());
        entry.extend_from_slice(&flags.to_le_bytes());
        entry.extend_from_slice(&offset.to_le_bytes());
        entry.extend_from_slice(&(BASE + offset).to_le_bytes());
        entry.extend_from_slice(&(BASE + offset).to_le_bytes());
        entry.extend_from_slice(&size.to_le_bytes());
        entry.extend_from_slice(&memsz.to_le_bytes());
        entry.extend_from_slice(&8u64.to_le_bytes());
        out[at..at + 56].copy_from_slice(&entry);
    };
    program(64, 1, 6, 0, end, 0x3000); // PT_LOAD, read and write
    if dynamic {
        program(120, 2, 6, 0x120, 0x40, 0x40); // PT_DYNAMIC
    }
    out
}

#[test]
fn a_static_start_ups_resolver_records_are_read_once_whichever_route_names_them() {
    // No dynamic table names `.rela.iplt`: its IRELATIVE records are applied by
    // the start-up through `__rela_iplt_start`, and reading only what the
    // dynamic table names would lose them.
    for dynamic in [false, true] {
        let image = image(&static_iplt(dynamic));
        let records: Vec<(u64, Applies, Option<i64>)> = image
            .relocations()
            .iter()
            .map(|relocation| (relocation.vaddr, relocation.applies, relocation.addend))
            .collect();
        assert_eq!(
            records,
            [(0x40_2000, Applies::Resolver, Some(0x40_1010))],
            "dynamic table present: {dynamic}"
        );
    }
}
