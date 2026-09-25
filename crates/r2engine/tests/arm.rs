//! An ARM program is read as its container states: per-function instruction
//! set, and the word order of its data.

use std::ops::Range;

use r2engine::discovery::Confidence;
use r2engine::program::{
    Arch, Container, Entry, EntryKind, Format, Mapping, OpenProgram, Permissions, Section, Segment,
    Source, Symbol, SymbolKind,
};
use r2engine::query::{AnnotationKind, Listing, Stop};

const ARM: u64 = 0x1000;
/// Stated only by the entry point, whose low bit is all that says Thumb.
const THUMB: u64 = 0x1008;
/// A pool after the Thumb code, which a `$a` mapping symbol states is ARM again.
const DATA: u64 = 0x100c;

const CODE: [u8; 0x14] = [
    // arm: ldr r0, [pc, #4], which reads the pool word; bx lr
    0x04, 0x00, 0x9f, 0xe5, 0x1e, 0xff, 0x2f, 0xe1, //
    // thumb: movs r0, #0; bx lr
    0x00, 0x20, 0x70, 0x47, //
    // data, which ARM decodes as `mov r0, #0` twice
    0x00, 0x00, 0xa0, 0xe3, 0x00, 0x00, 0xa0, 0xe3,
];

/// mvn r3, 0xf000; mov lr, pc; sub pc, r3, 0x3f; bx lr
///
/// ARM's pre-`blx` indirect call: the link register is loaded with the address
/// after the transfer, and `0xFFFF0FFF - 0x3F` is the kernel helper page.
const LINK_REGISTER_CALL: [u8; 16] = [
    0x0f, 0x3a, 0xe0, 0xe3, 0x0f, 0xe0, 0xa0, 0xe1, 0x3f, 0xf0, 0x43, 0xe2, 0x1e, 0xff, 0x2f, 0xe1,
];

struct Mixed {
    code: &'static [u8],
    container: Container,
}

impl Source for Mixed {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let offset = usize::try_from(vaddr.checked_sub(ARM)?).ok()?;
        let rest = self.code.get(offset..).filter(|rest| !rest.is_empty())?;
        Some(rest[..max.min(rest.len())].to_vec())
    }

    fn container(&self) -> &Container {
        &self.container
    }

    fn identity(&self) -> u64 {
        0
    }

    fn byte_revision(&self) -> u64 {
        0
    }

    fn written_since(&self, _revision: u64, _range: &Range<u64>) -> bool {
        false
    }
}

fn opened() -> OpenProgram<Mixed> {
    opened_as(r2il::Endianness::Little)
}

/// ARM code, a Thumb function stated only by the entry point, and an ARM pool.
fn opened_as(endian: r2il::Endianness) -> OpenProgram<Mixed> {
    let mut mixed = arm_only(&CODE, endian);
    // `$a` at the ARM code too, which the Thumb function after it outranks.
    for vaddr in [ARM, DATA] {
        mixed.container.symbols.push(Symbol {
            name: "$a".to_owned(),
            vaddr,
            size: 0,
            kind: SymbolKind::Mapping(Mapping::Arm),
            defined: true,
            thumb: false,
        });
    }
    mixed.container.entries.push(Entry {
        vaddr: THUMB,
        kind: EntryKind::Main,
        thumb: true,
    });
    OpenProgram::of(mixed)
}

fn opened_over(code: &'static [u8], endian: r2il::Endianness) -> OpenProgram<Mixed> {
    OpenProgram::of(arm_only(code, endian))
}

/// One ARM function spanning the whole of `code`.
fn arm_only(code: &'static [u8], endian: r2il::Endianness) -> Mixed {
    Mixed {
        code,
        container: Container {
            format: Format::Elf,
            arch: Arch {
                name: "arm".to_owned(),
                bits: 32,
                endian,
            },
            segments: vec![Segment {
                vaddr: ARM,
                vsize: code.len() as u64,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            }],
            sections: vec![Section {
                name: ".text".to_owned(),
                vaddr: ARM,
                vsize: code.len() as u64,
                is_code: true,
                loaded: true,
            }],
            symbols: vec![Symbol {
                name: "arm".to_owned(),
                vaddr: ARM,
                size: code.len() as u64,
                kind: SymbolKind::Function,
                defined: true,
                thumb: false,
            }],
            ..Container::default()
        },
    }
}

fn widths(program: &mut OpenProgram<Mixed>, start: u64) -> Vec<usize> {
    program
        .listing(Listing {
            start,
            stop: Stop::After(2),
        })
        .expect("it lists")
        .value
        .iter()
        .map(|line| line.bytes.len())
        .collect()
}

#[test]
fn arm_and_thumb_functions_in_one_program_each_decode_as_stated() {
    let mut program = opened();
    assert_eq!(widths(&mut program, ARM), [4, 4], "ARM decoded as Thumb");
    assert_eq!(widths(&mut program, THUMB), [2, 2], "Thumb decoded as ARM");
    assert_eq!(
        widths(&mut program, DATA),
        [4, 4],
        "a mapping symbol after a Thumb function did not switch back to ARM"
    );
}

#[test]
fn a_thumb_mapping_symbol_switches_one_arm_function_to_thumb() {
    // No entry and no symbol says Thumb here; only the `$t` does.
    let mapping = |name: &str, vaddr, mapping| Symbol {
        name: name.to_owned(),
        vaddr,
        size: 0,
        kind: SymbolKind::Mapping(mapping),
        defined: true,
        thumb: false,
    };
    let mut mixed = arm_only(&CODE, r2il::Endianness::Little);
    mixed.container.symbols.extend([
        mapping("$t", THUMB, Mapping::Thumb),
        mapping("$a", DATA, Mapping::Arm),
    ]);
    let mut program = OpenProgram::of(mixed);
    assert_eq!(widths(&mut program, ARM), [4, 4]);
    assert_eq!(widths(&mut program, THUMB), [2, 2]);
    assert_eq!(widths(&mut program, DATA), [4, 4]);
}

#[test]
fn a_pool_word_reads_in_the_container_s_order_not_the_decoder_s() {
    // BE8: little-endian instructions in a big-endian program.
    let holds = |endian| {
        let mut program = opened_as(endian);
        let answer = program
            .listing(Listing {
                start: ARM,
                stop: Stop::After(1),
            })
            .expect("it lists");
        answer.value[0]
            .annotations
            .iter()
            .find_map(|annotation| match annotation.kind {
                AnnotationKind::Holds { address, value, .. } => Some((address, value)),
                _ => None,
            })
    };
    assert_eq!(holds(r2il::Endianness::Little), Some((DATA, 0xe3a0_0000)));
    assert_eq!(holds(r2il::Endianness::Big), Some((DATA, 0x0000_a0e3)));
}

#[test]
fn a_branch_that_leaves_a_return_address_is_a_call() {
    // Sleigh lifts `sub pc, r3, 0x3f` as a branch, because that is the opcode;
    // the link register the specification names holding `0x100c` is what says
    // control comes back, so the transfer renders as a call.
    let mut program = opened_over(&LINK_REGISTER_CALL, r2il::Endianness::Little);
    let response = program
        .rendered(ARM, r2engine::RenderTier::C)
        .expect("it renders")
        .response;
    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{}",
        response.render_refusal,
        response.output
    );
    assert!(
        response.output.text().contains("fcn_ffff0fc0();"),
        "the helper call is missing:\n{}",
        response.output
    );
    // Control comes back, so the `bx lr` after the transfer is this body's.
    let listed = program
        .function_listing(ARM)
        .expect("it lists")
        .lines
        .value
        .iter()
        .map(|line| line.address - ARM)
        .collect::<Vec<_>>();
    assert_eq!(listed, [0x0, 0x4, 0x8, 0xc]);
}

#[test]
fn the_low_tier_spells_the_machine_registers() {
    let mut program = opened_over(&LINK_REGISTER_CALL, r2il::Endianness::Little);
    let lifted = program.lifted(ARM).expect("lifted");
    assert!(lifted.contains("Block 0x1000"), "{lifted}");
    // The link register is spelled, not offset-numbered, and the write to it
    // is what the call recovery reads.
    assert!(lifted.contains("lr"), "{lifted}");
    assert!(
        !lifted.contains("reg:0x58"),
        "unspelled register:\n{lifted}"
    );
}

/// `movw r0, thumb+1; bl atexit; bx lr`, a word nothing reads, `atexit: bx lr`,
/// and a Thumb `bx lr` whose word ARM cannot decode.
const HANDS_THUMB: [u8; 0x1c] = [
    0x15, 0x00, 0x01, 0xe3, 0x01, 0x00, 0x00, 0xeb, 0x1e, 0xff, 0x2f, 0xe1, //
    0x00, 0x00, 0x00, 0x00, //
    0x1e, 0xff, 0x2f, 0xe1, //
    0x70, 0x47, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
];

#[test]
fn a_thumb_pointer_handed_to_a_declared_handler_is_a_thumb_function() {
    // The pointer's low bit says Thumb, so the function is at the even
    // address and decodes as Thumb; the ARM decoder rejects its bytes.
    let mut mixed = arm_only(&HANDS_THUMB, r2il::Endianness::Little);
    mixed.container.symbols.push(Symbol {
        name: "atexit".to_owned(),
        vaddr: ARM + 0x10,
        size: 4,
        kind: SymbolKind::Function,
        defined: true,
        thumb: false,
    });
    let found = OpenProgram::of(mixed)
        .functions()
        .expect("discovery runs")
        .iter()
        .map(|one| (one.address, one.confidence, one.thumb))
        .collect::<Vec<_>>();
    assert_eq!(
        found,
        [
            (ARM, Confidence::Stated, false),
            (ARM + 0x10, Confidence::Stated, false),
            (ARM + 0x14, Confidence::Handed, true),
        ]
    );
}

/// Thumb: `cmp r0, #0; it eq; moveq r0, #1; bx lr`.
const IT_BLOCK: [u8; 8] = [0x00, 0x28, 0x08, 0xbf, 0x01, 0x20, 0x70, 0x47];

/// The bytes of one function and nothing else, as the body walk reads them.
struct Walked(&'static [u8]);

impl r2ssa::body::Program for Walked {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let offset = usize::try_from(vaddr.checked_sub(ARM)?).ok()?;
        let rest = self.0.get(offset..).filter(|rest| !rest.is_empty())?;
        Some(rest[..max.min(rest.len())].to_vec())
    }

    /// The function's bytes are one run of code.
    fn region(&self, vaddr: u64) -> Option<r2ssa::body::Region> {
        let end = ARM + self.0.len() as u64;
        (ARM..end).contains(&vaddr).then_some(r2ssa::body::Region {
            start: ARM,
            end,
            execute: true,
            write: false,
        })
    }

    fn is_entry(&self, _vaddr: u64) -> bool {
        false
    }
}

/// Sleigh's decode window, zero past the function's bytes.
fn window(at: u64) -> Vec<u8> {
    let mut fetch = IT_BLOCK[usize::try_from(at - ARM).expect("inside")..].to_vec();
    fetch.resize(16, 0);
    fetch
}

#[test]
fn an_instruction_an_it_predicates_is_listed_as_the_walk_decodes_it() {
    let thumb = r2sleigh_lift::embedded_machine("arm-thumb").expect("Thumb is compiled in");
    let guarded = ARM + 4;
    // The run the walk decodes: the entry afresh, each instruction after it continuing.
    let mut after = None;
    for at in [ARM, ARM + 2] {
        after = thumb
            .disasm
            .decode(&window(at), at, after)
            .expect("each decodes")
            .continuation;
    }
    let continuing = thumb
        .disasm
        .decode(&window(guarded), guarded, after)
        .expect("decodes");
    let fresh = thumb
        .disasm
        .decode(&window(guarded), guarded, None)
        .expect("decodes afresh");
    assert_ne!(
        continuing.syntax.text(),
        fresh.syntax.text(),
        "the `it` changed nothing, so this program proves nothing"
    );

    // The walk's lift of the guarded instruction is the continuing decode's.
    let body = r2ssa::body::lift_body(
        ARM,
        &thumb.disasm,
        &Walked(&IT_BLOCK),
        &std::collections::BTreeMap::new(),
    )
    .expect("the body walks");
    let walked: Vec<_> = body
        .blocks
        .iter()
        .flat_map(|block| {
            block
                .lifted
                .ops
                .iter()
                .enumerate()
                .filter_map(|(index, op)| {
                    (block.lifted.op_metadata(index)?.instruction_addr == Some(guarded))
                        .then_some(op.clone())
                })
        })
        .collect();
    let lifted = continuing.lifted.as_ref().expect("it lifts");
    assert_eq!(walked, lifted.ops);

    // pd and pdf spell it as that decode does, not as a decoder starting at it.
    let mut mixed = arm_only(&IT_BLOCK, r2il::Endianness::Little);
    mixed.container.symbols[0].thumb = true;
    let mut program = OpenProgram::of(mixed);
    let spelled = |lines: &[r2engine::query::Line]| {
        lines
            .iter()
            .find(|line| line.address == guarded)
            .and_then(|line| line.syntax.as_ref())
            .map(r2sleigh_lift::Syntax::text)
    };
    let pd = program
        .listing(Listing {
            start: ARM,
            stop: Stop::After(4),
        })
        .expect("it lists");
    assert_eq!(spelled(&pd.value), Some(continuing.syntax.text()), "pd");
    let pdf = program.function_listing(ARM).expect("it lists").lines;
    assert_eq!(spelled(&pdf.value), Some(continuing.syntax.text()), "pdf");
}

/// One Thumb function spanning the whole of `code`.
fn thumb_over(code: &'static [u8]) -> OpenProgram<Mixed> {
    let mut mixed = arm_only(code, r2il::Endianness::Little);
    mixed.container.symbols[0].thumb = true;
    OpenProgram::of(mixed)
}

/// What `pd` lists from the start of the program.
fn listed(program: &mut OpenProgram<Mixed>, count: usize) -> Vec<r2engine::query::Line> {
    program
        .listing(Listing {
            start: ARM,
            stop: Stop::After(count),
        })
        .expect("it lists")
        .value
}

/// Each line's offset, width and spelling.
fn shapes(lines: &[r2engine::query::Line]) -> Vec<(u64, usize, Option<String>)> {
    lines
        .iter()
        .map(|line| {
            let spelled = line.syntax.as_ref().map(r2sleigh_lift::Syntax::text);
            (line.address - ARM, line.bytes.len(), spelled)
        })
        .collect()
}

/// Thumb single-lane `vld2.8 {d0[0],d1[0]},[r0]`, which ARMneon.sinc leaves `unimpl`, then `bx lr`.
const UNBUILT: [u8; 6] = [0xa0, 0xf9, 0x0f, 0x01, 0x70, 0x47];

#[test]
fn an_instruction_sleigh_spells_but_cannot_build_is_listed_whole() {
    let lines = shapes(&listed(&mut thumb_over(&UNBUILT), 2));
    let spelled = lines[0].2.as_deref().unwrap_or_default();
    assert!(spelled.starts_with("vld2.8 "), "{lines:?}");
    assert_eq!(
        lines
            .iter()
            .map(|line| (line.0, line.1))
            .collect::<Vec<_>>(),
        [(0, 4), (4, 2)],
        "{lines:?}"
    );
    assert_eq!(lines[1].2.as_deref(), Some("bx lr"), "{lines:?}");
}

/// Thumb `cmp r0, #0; it eq; ldreq r0, [pc, #4]; bx lr`, a word, and the pool word the load reads.
const PREDICATED_POOL: [u8; 16] = [
    0x00, 0x28, 0x08, 0xbf, 0x01, 0x48, 0x70, 0x47, //
    0x00, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12,
];

#[test]
fn a_pool_load_an_it_predicates_still_reads_its_pool_word() {
    let lines = listed(&mut thumb_over(&PREDICATED_POOL), 4);
    let spelled = shapes(&lines)[2].2.clone().unwrap_or_default();
    assert!(
        spelled.starts_with("ldreq"),
        "the `it` changed nothing, so this program proves nothing: {spelled}"
    );
    let pool = ARM + 0xc;
    let kinds: Vec<_> = lines[2]
        .annotations
        .iter()
        .map(|one| one.kind.clone())
        .collect();
    let reads = AnnotationKind::Reads {
        address: pool,
        width: 4,
    };
    let holds = AnnotationKind::Holds {
        address: pool,
        width: 4,
        value: 0x1234_5678,
    };
    assert!(kinds.contains(&reads), "{spelled}: {kinds:?}");
    assert!(kinds.contains(&holds), "{spelled}: {kinds:?}");
}
