//! Decompiling from bytes and an address, with no radare2 in the process.

use r2abi::{CompilerSpec, Conventions};
use r2engine::native::{NativeTarget, decompile};

const BASE: u64 = 0x1000;

/// mov eax, edi; add eax, esi; ret
const ADD_TWO: &[u8] = &[0x89, 0xf8, 0x01, 0xf0, 0xc3];

/// A reader over one run of bytes mapped at `BASE`.
fn reader(bytes: &'static [u8]) -> impl Fn(u64, usize) -> Option<Vec<u8>> {
    move |vaddr, max| {
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let slice = bytes.get(offset..)?;
        (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
    }
}

#[test]
fn a_function_is_decompiled_from_bytes_alone() {
    let machine = r2sleigh_lift::embedded_machine("x86-64").expect("x86-64 machine");
    let conventions = Conventions::for_arch("x86-64", 64).expect("conventions");
    let convention = conventions.default_convention().expect("default");
    let compiler = CompilerSpec::parse(machine.compiler_spec);
    assert_eq!(compiler.stack_pointer.as_deref(), Some("RSP"));

    let target = NativeTarget {
        arch: &machine.arch,
        disasm: &machine.disasm,
        convention,
        compiler: &compiler,
    };
    let response = decompile(&target, BASE, "add_two", reader(ADD_TWO)).expect("decompile");

    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{}",
        response.render_refusal,
        response.output
    );
    // Both arguments arrive in the convention's registers and the sum comes
    // back, which is the whole claim this function makes.
    assert!(response.output.contains("add_two("), "{}", response.output);
    assert!(response.output.contains("EDI"), "{}", response.output);
    assert!(response.output.contains("ESI"), "{}", response.output);
    assert!(response.output.contains("return"), "{}", response.output);
}

#[test]
fn an_address_the_program_does_not_map_refuses() {
    let machine = r2sleigh_lift::embedded_machine("x86-64").expect("x86-64 machine");
    let conventions = Conventions::for_arch("x86-64", 64).expect("conventions");
    let convention = conventions.default_convention().expect("default");
    let compiler = CompilerSpec::parse(machine.compiler_spec);
    let target = NativeTarget {
        arch: &machine.arch,
        disasm: &machine.disasm,
        convention,
        compiler: &compiler,
    };
    let refusal = decompile(&target, 0x9000, "nowhere", reader(ADD_TWO)).expect_err("unmapped");
    assert_eq!(refusal.to_string(), "nothing mapped at 0x9000");
}
