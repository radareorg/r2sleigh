//! Recursive-descent body lift, from bytes at an address.

#![cfg(feature = "sleigh-config")]

use r2sleigh_lift::Disassembler;
use std::collections::BTreeMap;

use r2ssa::body::{Body, UnresolvedReason, lift_body};
use r2ssa::cfg::CFG;

const BASE: u64 = 0x1000;

fn addrs(body: &Body) -> Vec<u64> {
    body.blocks.iter().map(|block| block.lifted.addr).collect()
}

fn lifted(body: &Body) -> Vec<r2il::R2ILBlock> {
    body.blocks
        .iter()
        .map(|block| block.lifted.clone())
        .collect()
}

fn x86_64() -> Disassembler {
    Disassembler::from_sla(
        sleigh_config::processor_x86::SLA_X86_64,
        sleigh_config::processor_x86::PSPEC_X86_64,
        "x86-64",
    )
    .expect("x86-64 disassembler")
}

/// One run of bytes mapped at `BASE`, in a program that declares no other
/// function.
struct Fixture {
    bytes: &'static [u8],
    entries: &'static [u64],
}

impl r2ssa::body::Program for Fixture {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let slice = self.bytes.get(offset..)?;
        (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        self.entries.contains(&vaddr)
    }
}

fn reader(bytes: &'static [u8]) -> Fixture {
    Fixture {
        bytes,
        entries: &[],
    }
}

/// cmp rdi, 0; je +5; mov eax, 1; ret
const DIAMOND: &[u8] = &[
    0x48, 0x83, 0xff, 0x00, // 0x1000 cmp rdi, 0
    0x74, 0x05, // 0x1004 je 0x100b
    0xb8, 0x01, 0x00, 0x00, 0x00, // 0x1006 mov eax, 1
    0xc3, // 0x100b ret
];

#[test]
fn conditional_branch_splits_three_blocks() {
    let body = lift_body(BASE, &x86_64(), &reader(DIAMOND), &BTreeMap::new()).expect("body");
    assert_eq!(addrs(&body), vec![0x1000, 0x1006, 0x100b]);
    let sizes: Vec<u32> = body.blocks.iter().map(|block| block.lifted.size).collect();
    assert_eq!(sizes, vec![6, 5, 1]);
    // Every block keeps the bytes it is, for the capture to hand on.
    assert_eq!(body.blocks[2].bytes, vec![0xc3]);
    assert!(body.unresolved.is_empty(), "{:?}", body.unresolved);
}

#[test]
fn a_block_states_where_control_leaves_it() {
    use r2source::AdvisorySuccessorKind::{Direct, Fallthrough};

    let body = lift_body(BASE, &x86_64(), &reader(DIAMOND), &BTreeMap::new()).expect("body");
    assert_eq!(
        body.blocks[0].successors,
        vec![(Direct, 0x100b), (Fallthrough, 0x1006)]
    );
    assert_eq!(body.blocks[1].successors, vec![(Fallthrough, 0x100b)]);
    // A return leaves the function, so it names no successor at all.
    assert!(body.blocks[2].successors.is_empty());
}

#[test]
fn the_walk_feeds_the_graph() {
    let body = lift_body(BASE, &x86_64(), &reader(DIAMOND), &BTreeMap::new()).expect("body");
    let lifted = lifted(&body);
    let cfg = CFG::from_blocks(&lifted).expect("cfg");
    assert_eq!(cfg.entry, 0x1000);
    assert_eq!(cfg.num_blocks(), 3);
    let mut successors = cfg.successors(0x1000);
    successors.sort_unstable();
    assert_eq!(successors, vec![0x1006, 0x100b]);
}

/// call 0x1010; ret. The callee is outside what this reader maps, which is the
/// point: a call is a fact about the body, not an invitation to walk into one.
const CALLING: &[u8] = &[
    0xe8, 0x0b, 0x00, 0x00, 0x00, // 0x1000 call 0x1010
    0xc3, // 0x1005 ret
];

#[test]
fn a_call_is_recorded_and_the_block_runs_on() {
    let body = lift_body(BASE, &x86_64(), &reader(CALLING), &BTreeMap::new()).expect("body");
    assert_eq!(body.calls, vec![0x1010]);
    assert_eq!(body.blocks.len(), 1);
    assert_eq!(body.blocks[0].lifted.addr, 0x1000);
    assert_eq!(body.blocks[0].lifted.size, 6);
}

/// jmp rax
const INDIRECT: &[u8] = &[0xff, 0xe0];

#[test]
fn an_indirect_branch_is_refused_not_guessed() {
    let body = lift_body(BASE, &x86_64(), &reader(INDIRECT), &BTreeMap::new()).expect("body");
    assert_eq!(body.blocks.len(), 1);
    assert_eq!(
        body.unresolved
            .iter()
            .map(|stop| (stop.addr, stop.reason))
            .collect::<Vec<_>>(),
        vec![(0x1000, UnresolvedReason::IndirectBranch)]
    );
}

#[test]
fn a_dispatch_told_it_goes_nowhere_is_still_unresolved() {
    // A table of no entries resolves nothing. Read as resolved, the branch
    // had no successor and no stop, which claims control ends there.
    let dispatched = BTreeMap::from([(BASE, Vec::new())]);
    let body = lift_body(BASE, &x86_64(), &reader(INDIRECT), &dispatched).expect("body");
    assert_eq!(
        body.unresolved
            .iter()
            .map(|stop| (stop.addr, stop.reason))
            .collect::<Vec<_>>(),
        vec![(0x1000, UnresolvedReason::IndirectBranch)]
    );
    assert!(body.blocks[0].successors.is_empty());
}

/// A backward branch to the function's own entry: the walk terminates.
/// dec rdi; jne -5
const LOOP: &[u8] = &[
    0x48, 0xff, 0xcf, // 0x1000 dec rdi
    0x75, 0xfb, // 0x1003 jne 0x1000
    0xc3, // 0x1005 ret
];

#[test]
fn a_loop_terminates_and_keeps_one_block_per_leader() {
    let body = lift_body(BASE, &x86_64(), &reader(LOOP), &BTreeMap::new()).expect("body");
    assert_eq!(addrs(&body), vec![0x1000, 0x1005]);
}

#[test]
fn an_unmapped_entry_refuses() {
    let error =
        lift_body(0x9000, &x86_64(), &reader(DIAMOND), &BTreeMap::new()).expect_err("unmapped");
    assert_eq!(error.to_string(), "nothing mapped at 0x9000");
}

/// jmp 0x1010, where another function begins.
const TAIL: &[u8] = &[
    0xe9, 0x0b, 0x00, 0x00, 0x00, // 0x1000 jmp 0x1010
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // padding
    0x89, 0xf8, 0xc3, // 0x1010 mov eax, edi; ret
];

#[test]
fn a_branch_to_another_function_ends_the_body() {
    let program = Fixture {
        bytes: TAIL,
        entries: &[0x1010],
    };
    let body = lift_body(BASE, &x86_64(), &program, &BTreeMap::new()).expect("body");
    // One block, and the other function's code is not in it.
    assert_eq!(addrs(&body), vec![0x1000]);
    assert_eq!(body.tail_calls, vec![0x1010]);
    assert!(body.calls.is_empty());
}

#[test]
fn a_branch_to_a_function_the_program_does_not_declare_is_followed() {
    let program = Fixture {
        bytes: TAIL,
        entries: &[],
    };
    let body = lift_body(BASE, &x86_64(), &program, &BTreeMap::new()).expect("body");
    assert_eq!(addrs(&body), vec![0x1000, 0x1010]);
    assert!(body.tail_calls.is_empty());
}

/// `cmp r0, 0; it eq; moveq r0, 1; bx lr` in Thumb: the move runs only where
/// the comparison held.
const PREDICATED: &[u8] = &[
    0x00, 0x28, // cmp r0, 0
    0x08, 0xbf, // it eq
    0x01, 0x20, // moveq r0, 1
    0x70, 0x47, // bx lr
];

#[test]
fn a_run_keeps_the_decoder_context_that_predicates_it() {
    // Thumb's `it` says what the next instruction runs under, so a decoder
    // that starts afresh at each address reads it as unconditional. The walk
    // used to do exactly that and then disagreed with the block lift of the
    // same bytes about where control goes.
    let machine = r2sleigh_lift::embedded_machine("thumb").expect("thumb machine");
    let body =
        lift_body(BASE, &machine.disasm, &reader(PREDICATED), &BTreeMap::new()).expect("body");
    let ops = body
        .blocks
        .iter()
        .flat_map(|block| block.lifted.ops.iter())
        .collect::<Vec<_>>();
    assert!(
        ops.iter()
            .any(|op| matches!(op, r2il::R2ILOp::Select { .. })),
        "{ops:?}"
    );
}
