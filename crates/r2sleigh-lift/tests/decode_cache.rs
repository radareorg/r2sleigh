//! A decode reads the bytes it is handed, even where Sleigh parsed other bytes at the same address.

#![cfg(all(feature = "x86", feature = "sleigh-config"))]

fn lifted(disasm: &r2sleigh_lift::Disassembler, code: &[u8], at: u64) -> u32 {
    let mut window = code.to_vec();
    window.resize(16, 0);
    disasm.lift(&window, at).expect("lift").size
}

#[test]
fn a_patched_instruction_is_parsed_again() {
    let machine = r2sleigh_lift::embedded_machine("x86-64").expect("x86-64 machine");
    let at = 0x1000;
    // xor eax, eax; then nop and mov eax, 1 written over it.
    assert_eq!(lifted(&machine.disasm, &[0x31, 0xc0], at), 2);
    assert_eq!(lifted(&machine.disasm, &[0x90], at), 1);
    assert_eq!(lifted(&machine.disasm, &[0xb8, 0x01, 0, 0, 0], at), 5);
    assert_eq!(lifted(&machine.disasm, &[0x31, 0xc0], at), 2);
}
