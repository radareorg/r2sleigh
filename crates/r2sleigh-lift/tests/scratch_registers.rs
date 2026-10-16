//! The ARM and AArch64 processor specs mark Sleigh's scratch registers `hidden`, and each is
//! instruction-local: over random words, no lifted instruction reads one's value from before it.
#![cfg(feature = "arm")]

use r2il::Varnode;

const WORDS: u64 = 20_000;

fn scratch_is_instruction_local(name: &str, scratch: &[&str]) {
    let machine = r2sleigh_lift::embedded_machine(name).expect("embedded machine");
    let arch = machine.disasm.arch_spec();
    for register in scratch {
        let declared = arch
            .get_register(register)
            .unwrap_or_else(|| panic!("{name}: {register}"));
        assert!(declared.hidden, "{name}: {register} is not marked hidden");
        let storage = Varnode::register(declared.offset, declared.size);
        assert!(
            machine.disasm.hides_register(&storage),
            "{name}: {register}"
        );
    }
    let mut state = 0x2545_f491_4f6c_dd1du64 ^ name.len() as u64;
    let mut window = [0u8; 16];
    for at in (0..WORDS).map(|i| 0x10_0000 + 4 * i) {
        for chunk in window.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        let Ok(block) = machine.disasm.lift(&window, at) else {
            continue;
        };
        let hides = |vn: &Varnode| machine.disasm.hides_register(vn);
        let Some(accesses) = r2il::register_accesses(&block.ops, hides) else {
            continue;
        };
        let carried = accesses.reads.iter().find(|vn| hides(vn));
        assert!(
            carried.is_none(),
            "{name} {window:02x?}: {carried:?} carried in: {:?}",
            block.ops
        );
    }
}

const ARM: &[&str] = &[
    "tmpNG",
    "tmpZR",
    "tmpCY",
    "tmpOV",
    "shift_carry",
    "mult_addr",
];

#[test]
fn arm_scratch_registers_are_hidden_and_instruction_local() {
    scratch_is_instruction_local("arm", ARM);
    scratch_is_instruction_local("arm-thumb", ARM);
}

#[test]
fn aarch64_scratch_registers_are_hidden_and_instruction_local() {
    let scratch = [
        "tmpNG",
        "tmpZR",
        "tmpCY",
        "tmpOV",
        "shift_carry",
        "tmp_ldWn",
        "tmp_stXn",
        "TMPZ1",
        "TMPQ6",
    ];
    scratch_is_instruction_local("aarch64", &scratch);
}
