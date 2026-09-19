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

impl r2ssa::body::Program for Fixture {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let slice = self.bytes.get(offset..)?;
        (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        vaddr == BASE
    }
}

impl Program for Fixture {
    fn name_at(&self, vaddr: u64) -> Option<String> {
        (vaddr == BASE).then(|| self.name.to_owned())
    }

    fn import_at(&self, _vaddr: u64) -> Option<String> {
        None
    }
}

#[test]
fn a_function_is_decompiled_from_bytes_alone() {
    let machine = r2sleigh_lift::embedded_machine("x86-64").expect("x86-64 machine");
    let conventions = Conventions::for_arch("x86-64", 64).expect("conventions");
    let convention = conventions.default_convention().expect("default");
    let compiler = CompilerSpec::parse(machine.compiler_spec);
    assert_eq!(compiler.stack_pointer.as_deref(), Some("RSP"));

    let prototypes = r2abi::Prototypes::embedded();
    let target = NativeTarget {
        arch: &machine.arch,
        disasm: &machine.disasm,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
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
    let prototypes = r2abi::Prototypes::embedded();
    let target = NativeTarget {
        arch: &machine.arch,
        disasm: &machine.disasm,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
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
    let prototypes = r2abi::Prototypes::embedded();
    let target = NativeTarget {
        arch: &machine.arch,
        disasm: &machine.disasm,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
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

/// A program where the called address is a library function by name, as an
/// import stub is: no body worth reading, and a declared prototype instead.
struct Importing;

impl r2ssa::body::Program for Importing {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let slice = CALLER.get(offset..)?;
        (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        matches!(vaddr, BASE | 0x100a)
    }
}

impl Program for Importing {
    fn name_at(&self, vaddr: u64) -> Option<String> {
        self.import_at(vaddr)
            .or_else(|| (vaddr == BASE).then(|| "caller".to_owned()))
    }

    /// The binary says this address is an import's stub, which is what makes
    /// the declaration apply to it.
    fn import_at(&self, vaddr: u64) -> Option<String> {
        (vaddr == 0x100a).then(|| "strlen".to_owned())
    }
}

#[test]
fn a_declared_prototype_gives_an_import_its_arguments() {
    let machine = r2sleigh_lift::embedded_machine("x86-64").expect("x86-64 machine");
    let conventions = Conventions::for_arch("x86-64", 64).expect("conventions");
    let convention = conventions.default_convention().expect("default");
    let compiler = CompilerSpec::parse(machine.compiler_spec);
    let prototypes = r2abi::Prototypes::embedded();
    let target = NativeTarget {
        arch: &machine.arch,
        disasm: &machine.disasm,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
    };
    let response = decompile(&target, &Importing, BASE).expect("decompile");

    // strlen takes one argument, the convention says it arrives in rdi, and
    // the declaration says what it is.
    assert!(
        response.output.contains("strlen(const int8_t*)"),
        "{}",
        response.output
    );
    assert!(
        response.output.contains("strlen((const int8_t*)RDI_0)"),
        "{}",
        response.output
    );
    // The same marker the plugin's route prints when radare2 supplies one.
    assert!(
        response
            .output
            .contains("1 callee prototype supplied by radare2"),
        "{}",
        response.output
    );
}

/// add x0, x0, 1; ret
const AARCH64_ADD_ONE: &[u8] = &[
    0x00, 0x04, 0x00, 0x91, // 0x1000 add x0, x0, 1
    0xc0, 0x03, 0x5f, 0xd6, // 0x1004 ret
];

/// The same route on the other machine it claims.
#[test]
fn a_function_is_decompiled_on_aarch64_too() {
    let machine = r2sleigh_lift::embedded_machine("aarch64").expect("aarch64 machine");
    let conventions = Conventions::for_arch("aarch64", 64).expect("conventions");
    let convention = conventions.default_convention().expect("default");
    let compiler = CompilerSpec::parse(machine.compiler_spec);
    // The stack pointer is the specification's to name on every machine.
    assert_eq!(compiler.stack_pointer.as_deref(), Some("sp"));

    let prototypes = r2abi::Prototypes::embedded();
    let target = NativeTarget {
        arch: &machine.arch,
        disasm: &machine.disasm,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
    };
    let program = Fixture {
        bytes: AARCH64_ADD_ONE,
        name: "add_one",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");

    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{}",
        response.render_refusal,
        response.output
    );
    assert!(response.output.contains("add_one("), "{}", response.output);
    assert!(response.output.contains("X0_0"), "{}", response.output);
    assert!(response.output.contains("return"), "{}", response.output);
}
