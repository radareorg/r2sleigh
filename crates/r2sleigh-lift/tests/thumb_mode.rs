//! ARM states the instruction set per function, in the low bit of the symbol
//! that names it. The same SLA decodes both, so the mode is a processor
//! context and Thumb is the specification Ghidra ships with `TMode` set.
#![cfg(feature = "arm")]

fn decoded(name: &str, bytes: &[u8], at: u64) -> (u32, usize) {
    let machine = r2sleigh_lift::embedded_machine(name).expect("embedded machine");
    let mut window = bytes.to_vec();
    window.resize(16, 0);
    let block = machine.disasm.lift(&window, at).expect("lift");
    (block.size, block.ops.len())
}

#[test]
fn thumb_reads_a_two_byte_push_where_arm_reads_four() {
    // push {r7, lr}; sub sp, 8   at 0x10548 of test/bins/elf/thumb-movpcadd
    let prologue = [0x80u8, 0xb5, 0x82, 0xb0];
    assert_eq!(decoded("arm-thumb", &prologue, 0x10548).0, 2);
    assert_eq!(decoded("arm", &prologue, 0x10548).0, 4);
}

#[test]
fn arm_and_thumb_are_the_same_instruction_set() {
    let arm = r2sleigh_lift::embedded_machine("arm").expect("arm machine");
    let thumb = r2sleigh_lift::embedded_machine("arm-thumb").expect("thumb machine");
    assert_eq!(arm.arch.name, thumb.arch.name);
}

/// The same move under `it eq` and under `it ne`: `cmp r0, #0; it <cond>; mov<cond> r0, #1`.
const EQ: [u8; 6] = [0x00, 0x28, 0x08, 0xbf, 0x01, 0x20];
const NE: [u8; 6] = [0x00, 0x28, 0x18, 0xbf, 0x01, 0x20];
const BASE: u64 = 0x1000;

fn window(code: &[u8], at: u64) -> Vec<u8> {
    let mut fetch = code[usize::try_from(at - BASE).expect("inside")..].to_vec();
    fetch.resize(16, 0);
    fetch
}

#[test]
fn a_decode_keeps_only_the_context_its_own_run_left() {
    use r2sleigh_lift::{Disassembler, TrustedSleighProfile};
    let profile = TrustedSleighProfile::ArmThumbLe;
    let ours = Disassembler::shared_profile_for_analysis(profile).expect("Thumb");
    let theirs = Disassembler::shared_profile_for_analysis(profile).expect("Thumb");
    assert!(ours.shares_loaded_specification(&theirs));
    let moved = BASE + 4;
    let spelled = |after| {
        ours.decode(&window(&EQ, moved), moved, after)
            .expect("decodes")
            .syntax
            .text()
    };
    let fresh = spelled(None);
    // The `it` of a run, and where it leaves the decoder for the move.
    let run = |disasm: &Disassembler, code: &[u8]| {
        [BASE, BASE + 2].into_iter().fold(None, |after, at| {
            let one = disasm.decode(&window(code, at), at, after);
            one.expect("decodes").continuation
        })
    };
    let own = spelled(run(&ours, &EQ));
    assert_ne!(own, fresh, "the `it` changed nothing");
    // Another run on the specification in between leaves its `it ne` there, which ours must not read.
    let after = run(&ours, &EQ);
    run(&theirs, &NE);
    assert_eq!(spelled(after), fresh, "continued under {own}");
}
