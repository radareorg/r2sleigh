//! `0F 18 /0-3` with a memory operand are PREFETCHh and `0F 1A`/`0F 1B` with one are MPX (Intel SDM
//! Vol. 2); the catch-all hint NOP of `0F 18`-`0F 1F` must not take them (they state `opsize`, as it does).
#![cfg(feature = "x86")]

mod x86_machine;

use x86_machine::{HELD, Machine};

fn spelled(bytes: &[u8]) -> String {
    let machine = r2sleigh_lift::embedded_machine("x86-64").expect("x86-64");
    let mut fetch = bytes.to_vec();
    fetch.resize(16, 0);
    let one = machine
        .disasm
        .decode(&fetch, 0x1000, None)
        .expect("decodes");
    assert_eq!(one.syntax.size, bytes.len(), "{bytes:02x?}");
    one.syntax.text()
}

#[test]
fn a_memory_prefetch_hint_is_not_a_nop() {
    for (reg, name) in ["prefetchnta", "prefetcht0", "prefetcht1", "prefetcht2"]
        .into_iter()
        .enumerate()
    {
        let modrm = u8::try_from(reg).unwrap() << 3 | 0x06;
        for prefix in [&[][..], &[0x66][..]] {
            let bytes = [prefix, &[0x0f, 0x18, modrm]].concat();
            let text = spelled(&bytes);
            assert!(text.starts_with(name), "{bytes:02x?}: {text}");
            assert!(
                Machine::x86_64().lift(&bytes).is_empty(),
                "{name} has no effect"
            );
        }
    }
    assert!(
        spelled(&[0x0f, 0x18, 0x26]).starts_with("nop"),
        "/4 is reserved"
    );
    assert!(
        spelled(&[0x0f, 0x18, 0xc0]).starts_with("nop"),
        "a register operand is reserved"
    );
}

#[test]
fn a_bound_move_loads_the_bound_register() {
    let machine = Machine::x86_64();
    // bndmov bnd0, [rsi]: 16 bytes in 64-bit mode
    let state = machine.run(&[0x66, 0x0f, 0x1a, 0x06], &[]);
    assert_eq!(machine.read(&state, "BND0"), HELD);
    // bndldx bnd0, [rsi] (no prefix) reads the same cell in this model
    assert!(spelled(&[0x0f, 0x1a, 0x06]).starts_with("bndldx"));
    // bndmov bnd0, bnd1 (66 0F 1A /r, mod 3): the register form copies the 16 bytes
    let state = machine.run(&[0x66, 0x0f, 0x1a, 0xc1], &[("BND1", HELD)]);
    assert_eq!(machine.read(&state, "BND0"), HELD);
}

#[test]
fn a_bound_move_register_form_without_a_prefix_stays_the_hint_nop() {
    assert!(spelled(&[0x0f, 0x1a, 0xc0]).starts_with("nop"));
    assert!(spelled(&[0x0f, 0x1b, 0xc0]).starts_with("nop"));
}
