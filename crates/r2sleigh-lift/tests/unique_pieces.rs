//! Sleigh reads a piece of a temporary in place since GP-5581 (`result:4` of an 8-byte `result`);
//! the lift reads every temporary exactly where the instruction wrote it.
use std::collections::BTreeSet;

use r2il::SpaceId;

#[cfg(feature = "x86")]
mod x86_machine;

fn reads_only_what_it_wrote(name: &str, word: &[u8]) {
    let machine = r2sleigh_lift::embedded_machine(name).expect("embedded machine");
    let mut window = word.to_vec();
    window.resize(16, 0);
    let block = machine.disasm.lift(&window, 0x1000).expect("lifts");
    let mut written = BTreeSet::new();
    for op in &block.ops {
        for read in op
            .inputs()
            .into_iter()
            .filter(|v| v.space == SpaceId::Unique)
        {
            assert!(
                written.contains(&(read.offset, read.size)),
                "{name} {word:02x?} reads {read:?} where it wrote nothing: {:#?}",
                block.ops
            );
        }
        if let Some(out) = op.output().filter(|v| v.space == SpaceId::Unique) {
            written.insert((out.offset, out.size));
        }
    }
}

#[cfg(feature = "x86")]
#[test]
fn a_vector_load_read_in_halves_reads_pieces_of_it() {
    // movapd xmm0, [rip + 0x204a]: XMM0's quadwords are the loaded temporary's bytes 0 and 8
    reads_only_what_it_wrote("x86-64", &[0x66, 0x0f, 0x28, 0x05, 0x4a, 0x20, 0, 0]);
}

#[cfg(feature = "arm")]
#[test]
fn a_truncated_temporary_under_a_condition_reads_its_write() {
    // add w11, w10, w11, uxtb: the low byte of a copy of w11
    reads_only_what_it_wrote("aarch64", &[0x4b, 0x01, 0x2b, 0x0b]);
    // smlsldcc r13, r13, sp, sp: RdLo is `result:4`, and the condition renames what it writes
    reads_only_what_it_wrote("arm", &[0x5d, 0xdd, 0x4b, 0x37]);
    // sxtahcs: a rotated register exported at 4 bytes, extended from 2
    reads_only_what_it_wrote("arm", &[0x7e, 0xff, 0xb3, 0x26]);
}

/// GP-6061 writes VPADDW's and VPADDD's lanes into a 16-byte temporary in place; each lane is the
/// wrapped sum of its operands' lanes (Intel SDM Vol. 2B, PADDB/PADDW/PADDD/PADDQ).
#[cfg(feature = "x86")]
#[test]
fn lanes_written_into_a_temporary_in_place_are_read_back_whole() {
    let machine = x86_machine::Machine::x86_64();
    let words = [
        ("XMM7", 0x0001_ffff_8000_7fff_0002_0003_fffe_0001),
        ("XMM4", 0x0001_0001_8000_0001_0003_0004_0003_ffff),
    ];
    // vpaddw xmm0, xmm7, xmm4
    let state = &machine.run(&[0xc5, 0xc1, 0xfd, 0xc4], &words);
    assert_eq!(
        machine.read(state, "XMM0"),
        0x0002_0000_0000_8000_0005_0007_0001_0000
    );
    // vpaddd xmm1, xmm1, [rsi]: the cell's doublewords added to XMM1's
    let dwords = [("XMM1", 0x0000_0001_ffff_ffff_8888_8888_0000_0001)];
    let state = &machine.run(&[0xc5, 0xf1, 0xfe, 0x0e], &dwords);
    assert_eq!(
        machine.read(state, "XMM1"),
        0x1111_2223_3333_4443_dddd_eeee_7777_8889
    );
}
