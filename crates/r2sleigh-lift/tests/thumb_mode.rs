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
