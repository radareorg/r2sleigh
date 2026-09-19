//! Decompiling from bytes and an address, with no radare2 in the process.

use r2abi::{CompilerSpec, Conventions};
use r2engine::native::{NativeTarget, Program, decompile};

const BASE: u64 = 0x1000;

/// mov eax, edi; add eax, esi; ret
const ADD_TWO: &[u8] = &[0x89, 0xf8, 0x01, 0xf0, 0xc3];

/// call 0x100a; ret -- with `add_two` at 0x100a.
const CALLER: &[u8] = &[
    0xe8, 0x05, 0x00, 0x00, 0x00, // 0x1000 call 0x100a
    0xc3, // 0x1005 ret
    0x00, 0x00, 0x00, 0x00, // padding to 0x100a
    0x89, 0xf8, 0x01, 0xf0, 0xc3, // 0x100a add_two
];

/// One run of bytes mapped at `BASE`, under one name.
struct Fixture {
    bytes: &'static [u8],
    name: &'static str,
}

impl Program for Fixture {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let slice = self.bytes.get(offset..)?;
        (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
    }

    fn name_at(&self, vaddr: u64) -> Option<String> {
        (vaddr == BASE).then(|| self.name.to_owned())
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
    let program = Fixture {
        bytes: ADD_TWO,
        name: "add_two",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");

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
    let program = Fixture {
        bytes: ADD_TWO,
        name: "add_two",
    };
    let refusal = decompile(&target, &program, 0x9000).expect_err("unmapped");
    assert_eq!(refusal.to_string(), "nothing mapped at 0x9000");
}

#[test]
fn a_call_is_rendered_from_the_callee_body() {
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
    let program = Fixture {
        bytes: CALLER,
        name: "caller",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");

    // The callee's own body is what says what the call takes and returns, and
    // it is walked for exactly that.
    assert!(
        response
            .output
            .contains("uint32_t sub_100a(uint32_t, uint32_t)"),
        "{}",
        response.output
    );
    assert!(response.output.contains("sub_100a("), "{}", response.output);
}
