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

/// A thunk that hands back the address the call pushed, and a caller that
/// forms an address from it: `call 0x100b; lea rax, [rsi + 0x10]; ret` over
/// `mov rsi, [rsp]; ret`.
const PC_THUNK: &[u8] = &[
    0xe8, 0x06, 0x00, 0x00, 0x00, // 0x1000 call 0x100b
    0x48, 0x8d, 0x46, 0x10, // 0x1005 lea rax, [rsi + 0x10]
    0xc3, // 0x1009 ret
    0x90, // 0x100a padding
    0x48, 0x8b, 0x34, 0x24, // 0x100b mov rsi, [rsp]
    0xc3, // 0x100f ret
];

/// One run of bytes mapped at `BASE`, under one name.
struct Fixture {
    bytes: &'static [u8],
    name: &'static str,
    /// The register a call returns through, where the test needs one.
    link: Option<r2il::Varnode>,
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

    fn return_address_register(&self) -> Option<r2il::Varnode> {
        self.link.clone()
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
        cpu: machine.cpu,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
    };
    let program = Fixture {
        bytes: ADD_TWO,
        name: "add_two",
        link: None,
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
        cpu: machine.cpu,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
    };
    let program = Fixture {
        bytes: ADD_TWO,
        name: "add_two",
        link: None,
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
        cpu: machine.cpu,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
    };
    let program = Fixture {
        bytes: CALLER,
        name: "caller",
        link: None,
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

#[test]
fn a_callee_that_returns_the_pushed_address_gives_its_caller_a_constant() {
    let machine = r2sleigh_lift::embedded_machine("x86-64").expect("x86-64 machine");
    let conventions = Conventions::for_arch("x86-64", 64).expect("conventions");
    let convention = conventions.default_convention().expect("default");
    let compiler = CompilerSpec::parse(machine.compiler_spec);
    let prototypes = r2abi::Prototypes::embedded();
    let target = NativeTarget {
        arch: &machine.arch,
        disasm: &machine.disasm,
        cpu: machine.cpu,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
    };
    let program = Fixture {
        bytes: PC_THUNK,
        name: "pc_caller",
        link: None,
    };
    let response = decompile(&target, &program, BASE).expect("decompile");

    // The pushed address is the one after the call: 0x1005 + 0x10.
    assert!(
        response.output.contains("0x1015"),
        "the address the thunk's result names is not spelled: {}",
        response.output
    );
    // Spelled at its use, the call's own result binding has no reader left.
    assert!(
        !response.output.contains("RSI"),
        "the result binding outlived its readers: {}",
        response.output
    );
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
        cpu: machine.cpu,
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
        cpu: machine.cpu,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
    };
    let program = Fixture {
        bytes: AARCH64_ADD_ONE,
        name: "add_one",
        link: None,
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

/// ldr r0, [pc, 4]; mov r0, 0; bx lr; .word -- the load's value is overwritten.
const ARM_DEAD_LOAD: &[u8] = &[
    0x04, 0x00, 0x9f, 0xe5, // 0x1000 ldr r0, [pc, 4]  -> 0x100c
    0x00, 0x00, 0xa0, 0xe3, // 0x1004 mov r0, 0
    0x1e, 0xff, 0x2f, 0xe1, // 0x1008 bx lr
    0x78, 0x56, 0x34, 0x12, // 0x100c the word it loads
];

/// A read the program performs is rendered even when nothing uses it.
///
/// `mov r0, 0` overwrites what the load produced, so the value is dead; the
/// read still happened, so the statement stands and discards its result
/// rather than disappearing.
#[test]
fn a_load_nothing_reads_still_reads() {
    let machine = r2sleigh_lift::embedded_machine("arm").expect("arm machine");
    let conventions = Conventions::for_arch("arm", 32).expect("conventions");
    let convention = conventions.default_convention().expect("default");
    let compiler = CompilerSpec::parse(machine.compiler_spec);
    let prototypes = r2abi::Prototypes::embedded();
    let target = NativeTarget {
        arch: &machine.arch,
        disasm: &machine.disasm,
        cpu: machine.cpu,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
    };
    let program = Fixture {
        bytes: ARM_DEAD_LOAD,
        name: "dead_load",
        link: None,
    };
    let response = decompile(&target, &program, BASE).expect("decompile");

    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{}",
        response.render_refusal,
        response.output
    );
    assert!(
        response.output.contains("(void)*"),
        "the discarded read is missing:\n{}",
        response.output
    );
}

/// mvn r3, 0xf000; mov lr, pc; sub pc, r3, 0x3f; bx lr
///
/// ARM's pre-`blx` indirect call: the link register is loaded with the address
/// after the transfer, and `0xFFFF0FFF - 0x3F` is the kernel helper page.
const ARM_LINK_REGISTER_CALL: &[u8] = &[
    0x0f, 0x3a, 0xe0, 0xe3, // 0x1000 mvn r3, 0xf000
    0x0f, 0xe0, 0xa0, 0xe1, // 0x1004 mov lr, pc
    0x3f, 0xf0, 0x43, 0xe2, // 0x1008 sub pc, r3, 0x3f
    0x1e, 0xff, 0x2f, 0xe1, // 0x100c bx lr
];

/// A branch that leaves the return address behind is a call.
///
/// Sleigh lifts `sub pc, r3, 0x3f` as a branch, because that is the opcode.
/// The link register holding `0x100c` is what says control comes back, so the
/// walk follows it and the transfer renders as a call.
#[test]
fn a_branch_that_leaves_a_return_address_is_a_call() {
    let machine = r2sleigh_lift::embedded_machine("arm").expect("arm machine");
    let conventions = Conventions::for_arch("arm", 32).expect("conventions");
    let convention = conventions.default_convention().expect("default");
    let compiler = CompilerSpec::parse(machine.compiler_spec);
    // The specification names it; nothing here guesses which register it is.
    let name = compiler.return_address.clone().expect("a link register");
    let link = machine
        .arch
        .registers
        .iter()
        .find(|register| register.name.eq_ignore_ascii_case(&name))
        .map(|register| r2il::Varnode {
            space: r2il::SpaceId::Register,
            offset: register.offset,
            size: register.size,
            meta: None,
        })
        .expect("the link register is in the architecture");

    let prototypes = r2abi::Prototypes::embedded();
    let target = NativeTarget {
        arch: &machine.arch,
        disasm: &machine.disasm,
        cpu: machine.cpu,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
    };
    let program = Fixture {
        bytes: ARM_LINK_REGISTER_CALL,
        name: "helper_call",
        link: Some(link),
    };
    let response = decompile(&target, &program, BASE).expect("decompile");

    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{}",
        response.render_refusal,
        response.output
    );
    assert!(
        response.output.contains("0xffff0fc0"),
        "the helper call is missing:\n{}",
        response.output
    );
}

/// The analysis tier can be asked for on its own, without asking for C.
///
/// A defect in the output is either already visible here or belongs to the
/// lowering below it, which is the whole reason the tier is printable.
#[test]
fn the_medium_tier_is_readable_without_rendering() {
    let machine = r2sleigh_lift::embedded_machine("arm").expect("arm machine");
    let conventions = Conventions::for_arch("arm", 32).expect("conventions");
    let convention = conventions.default_convention().expect("default");
    let compiler = CompilerSpec::parse(machine.compiler_spec);
    let prototypes = r2abi::Prototypes::embedded();
    let target = NativeTarget {
        arch: &machine.arch,
        disasm: &machine.disasm,
        cpu: machine.cpu,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
    };
    let program = Fixture {
        bytes: ARM_DEAD_LOAD,
        name: "dead_load",
        link: None,
    };
    let artifact = r2engine::native::prepared(&target, &program, BASE).expect("prepared");
    let dump = artifact.artifact().function().dump();

    // The load is in the tier whether or not anything renders it, and the
    // operations are spelled by `SSAOp`'s own Display rather than by Debug.
    assert!(dump.contains("Block 0x1000:"), "{dump}");
    assert!(dump.contains("LOAD [ram]"), "{dump}");
    assert!(!dump.contains("SSAVar {"), "derived Debug leaked:\n{dump}");
}

/// The structured tier is the tree the C is generated from.
///
/// Read against the C, it says whether a defect is already in the tree or
/// belongs to the generation below it.
#[test]
fn the_structured_tier_is_the_tree_the_c_comes_from() {
    let machine = r2sleigh_lift::embedded_machine("arm").expect("arm machine");
    let conventions = Conventions::for_arch("arm", 32).expect("conventions");
    let convention = conventions.default_convention().expect("default");
    let compiler = CompilerSpec::parse(machine.compiler_spec);
    let prototypes = r2abi::Prototypes::embedded();
    let target = NativeTarget {
        arch: &machine.arch,
        disasm: &machine.disasm,
        cpu: machine.cpu,
        convention,
        compiler: &compiler,
        prototypes: &prototypes,
    };
    let program = Fixture {
        bytes: ARM_DEAD_LOAD,
        name: "dead_load",
        link: None,
    };
    let tree = r2engine::native::structured(&target, &program, BASE)
        .expect("structured")
        .output;
    let c = decompile(&target, &program, BASE)
        .expect("decompile")
        .output;

    assert!(tree.contains("Function: dead_load"), "{tree}");
    // The statements are spelled by the emitter that writes the C, so the two
    // tiers disagree about their shape and about nothing else.
    assert!(tree.contains("(void)*"), "{tree}");
    assert!(c.contains("(void)*"), "{c}");
}
