//! Recursive-descent body lift, from bytes at an address.

#![cfg(feature = "sleigh-config")]

use r2sleigh_lift::Disassembler;
use r2ssa::body::{UnresolvedReason, lift_body};
use r2ssa::cfg::CFG;

const BASE: u64 = 0x1000;

fn x86_64() -> Disassembler {
    Disassembler::from_sla(
        sleigh_config::processor_x86::SLA_X86_64,
        sleigh_config::processor_x86::PSPEC_X86_64,
        "x86-64",
    )
    .expect("x86-64 disassembler")
}

/// A reader over one run of bytes mapped at `BASE`.
fn reader(bytes: &'static [u8]) -> impl Fn(u64, usize) -> Option<Vec<u8>> {
    move |vaddr, max| {
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let slice = bytes.get(offset..)?;
        (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
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
    let body = lift_body(BASE, &x86_64(), reader(DIAMOND)).expect("body");
    let addrs: Vec<u64> = body.blocks.iter().map(|block| block.addr).collect();
    assert_eq!(addrs, vec![0x1000, 0x1006, 0x100b]);
    assert_eq!(body.blocks[0].size, 6);
    assert_eq!(body.blocks[1].size, 5);
    assert_eq!(body.blocks[2].size, 1);
    assert!(body.unresolved.is_empty(), "{:?}", body.unresolved);
}

#[test]
fn the_walk_feeds_the_graph() {
    let body = lift_body(BASE, &x86_64(), reader(DIAMOND)).expect("body");
    let cfg = CFG::from_blocks(&body.blocks).expect("cfg");
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
    let body = lift_body(BASE, &x86_64(), reader(CALLING)).expect("body");
    assert_eq!(body.calls, vec![0x1010]);
    assert_eq!(body.blocks.len(), 1);
    assert_eq!(body.blocks[0].addr, 0x1000);
    assert_eq!(body.blocks[0].size, 6);
}

/// jmp rax
const INDIRECT: &[u8] = &[0xff, 0xe0];

#[test]
fn an_indirect_branch_is_refused_not_guessed() {
    let body = lift_body(BASE, &x86_64(), reader(INDIRECT)).expect("body");
    assert_eq!(body.blocks.len(), 1);
    assert_eq!(
        body.unresolved
            .iter()
            .map(|stop| (stop.addr, stop.reason))
            .collect::<Vec<_>>(),
        vec![(0x1000, UnresolvedReason::IndirectBranch)]
    );
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
    let body = lift_body(BASE, &x86_64(), reader(LOOP)).expect("body");
    let addrs: Vec<u64> = body.blocks.iter().map(|block| block.addr).collect();
    assert_eq!(addrs, vec![0x1000, 0x1005]);
}

#[test]
fn an_unmapped_entry_refuses() {
    let error = lift_body(0x9000, &x86_64(), reader(DIAMOND)).expect_err("unmapped");
    assert_eq!(error.to_string(), "nothing mapped at 0x9000");
}
