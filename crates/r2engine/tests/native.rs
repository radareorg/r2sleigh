//! Decompiling from bytes and an address, with no radare2 in the process.

mod common;

use std::collections::BTreeMap;

use common::TABLE_SWITCH;

use r2abi::{CompilerSpec, Conventions, Prototypes};
use r2engine::native::{NativeTarget, Program, call_effect, decompile};
use r2sleigh_lift::EmbeddedMachine;
use r2source::SourceCallEffect;
use r2ssa::{InstPayload, SSAOp};

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

/// Every return sits behind the dispatch; before it the body keeps a local whose address escapes.
const SPILLED_SWITCH: &[u8] = &[
    0x48, 0x83, 0xec, 0x08, // 1000 sub rsp, 8
    0xc7, 0x04, 0x24, 0x07, 0x00, 0x00, 0x00, // 1004 mov dword [rsp], 7
    0x48, 0x89, 0xe0, // 100b mov rax, rsp
    0x48, 0x89, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // 100e mov [0x2000], rax
    0x83, 0xe7, 0x03, // 1016 and edi, 3
    0xff, 0x24, 0xfd, 0x48, 0x10, 0x00, 0x00, // 1019 jmp [rdi*8 + 0x1048]
    0xb8, 0x0a, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x08, 0xc3, // 1020 case 0
    0xb8, 0x14, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x08, 0xc3, // 102a case 1
    0xb8, 0x1e, 0x00, 0x00, 0x00, 0x48, 0x83, 0xc4, 0x08, 0xc3, // 1034 case 2
    0x8b, 0x04, 0x24, 0x48, 0x83, 0xc4, 0x08, 0xc3, // 103e case 3: return the local
    0x00, 0x00, // 1046 padding
    0x20, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1048 -> 0x1020
    0x2a, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1050 -> 0x102a
    0x34, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1058 -> 0x1034
    0x3e, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1060 -> 0x103e
];

/// One embedded machine with what the engine reads beside it.
struct Machine {
    embedded: EmbeddedMachine,
    conventions: Conventions,
    /// What each convention says a call does to this machine's registers.
    effects: BTreeMap<String, Option<SourceCallEffect>>,
    compiler: CompilerSpec,
    prototypes: Prototypes,
}

impl Machine {
    fn new(sleigh: &str, family: &str, bits: u32) -> Self {
        let embedded = r2sleigh_lift::embedded_machine(sleigh).expect("embedded machine");
        let conventions = Conventions::for_arch(family, bits).expect("conventions");
        let effects = conventions
            .names()
            .map(|name| {
                let convention = conventions.get(name).expect("named convention");
                (name.to_owned(), call_effect(&embedded.arch, convention))
            })
            .collect();
        let compiler = CompilerSpec::parse(embedded.compiler_spec);
        Self {
            embedded,
            conventions,
            effects,
            compiler,
            prototypes: Prototypes::embedded(),
        }
    }

    /// The machine under its default convention.
    fn target(&self) -> NativeTarget<'_> {
        self.under(
            self.conventions
                .default_name()
                .expect("a default convention"),
        )
    }

    /// The machine under one named convention.
    fn under(&self, name: &str) -> NativeTarget<'_> {
        NativeTarget {
            arch: &self.embedded.arch,
            disasm: &self.embedded.disasm,
            cpu: self.embedded.cpu,
            convention: self.conventions.get(name).expect("the named convention"),
            call_effect: self.effects[name].as_ref(),
            compiler: &self.compiler,
            prototypes: &self.prototypes,
        }
    }
}

/// `len` bytes of code mapped at `BASE`, as one region an instruction can run in.
fn code_region(len: usize, vaddr: u64) -> Option<r2ssa::body::Region> {
    let end = BASE + len as u64;
    (BASE..end).contains(&vaddr).then_some(r2ssa::body::Region {
        start: BASE,
        end,
        file_end: end,
        execute: true,
        write: false,
    })
}

/// One run of bytes mapped at `BASE`, under one name.
///
/// Owned, so a test can generate the program it decompiles rather than only
/// spell it out.
struct Fixture {
    bytes: Vec<u8>,
    name: &'static str,
}

impl r2ssa::body::Program for Fixture {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let slice = self.bytes.get(offset..)?;
        (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
    }

    fn region(&self, vaddr: u64) -> Option<r2ssa::body::Region> {
        code_region(self.bytes.len(), vaddr)
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        vaddr == BASE
    }
}

impl Program for Fixture {
    fn holds_static_data(&self, _vaddr: u64) -> bool {
        // The fixture maps one run of instruction bytes and declares no
        // sections, so nothing in it is a place a string could live.
        false
    }

    /// Nothing here is loaded, so nothing is written by a loader.
    fn loader_writes(&self, _range: &std::ops::Range<u64>) -> bool {
        false
    }

    fn extents(&self) -> &r2types::ProgramExtents {
        const NONE: &r2types::ProgramExtents = &r2types::ProgramExtents::none();
        NONE
    }

    fn name_at(&self, vaddr: u64) -> Option<String> {
        (vaddr == BASE).then(|| self.name.to_owned())
    }

    fn import_at(&self, _vaddr: u64) -> Option<String> {
        None
    }
}

#[test]
fn a_function_is_decompiled_from_bytes_alone() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    assert_eq!(machine.compiler.stack_pointer.as_deref(), Some("RSP"));

    let target = machine.target();
    let program = Fixture {
        bytes: ADD_TWO.to_vec(),
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
    assert!(
        response.output.text().contains("add_two("),
        "{}",
        response.output
    );
    assert!(
        response.output.text().contains("EDI"),
        "{}",
        response.output
    );
    assert!(
        response.output.text().contains("ESI"),
        "{}",
        response.output
    );
    assert!(
        response.output.text().contains("return"),
        "{}",
        response.output
    );
}

#[test]
fn an_address_the_program_does_not_map_refuses() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: ADD_TWO.to_vec(),
        name: "add_two",
    };
    let refusal = decompile(&target, &program, 0x9000).expect_err("unmapped");
    assert_eq!(refusal.to_string(), "nothing mapped at 0x9000");
}

#[test]
fn a_call_is_rendered_from_the_callee_body() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: CALLER.to_vec(),
        name: "caller",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");

    // The callee's own body is what says what the call takes and returns, and
    // it is walked for exactly that.
    assert!(
        response
            .output
            .text()
            .contains("uint32_t fcn_100a(uint32_t, uint32_t)"),
        "{}",
        response.output
    );
    assert!(
        response.output.text().contains("fcn_100a("),
        "{}",
        response.output
    );
}

/// `CALLER`, whose callee's bytes cannot be read without the program panicking:
/// a defect reached only by reading the callee.
struct PanickingCallee;

impl r2ssa::body::Program for PanickingCallee {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        assert!(vaddr < 0x100a, "a defect reading the callee at {vaddr:#x}");
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let slice = CALLER.get(offset..)?;
        (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
    }

    fn region(&self, vaddr: u64) -> Option<r2ssa::body::Region> {
        code_region(CALLER.len(), vaddr)
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        matches!(vaddr, BASE | 0x100a)
    }
}

impl Program for PanickingCallee {
    fn holds_static_data(&self, _vaddr: u64) -> bool {
        false
    }

    fn loader_writes(&self, _range: &std::ops::Range<u64>) -> bool {
        false
    }

    fn extents(&self) -> &r2types::ProgramExtents {
        const NONE: &r2types::ProgramExtents = &r2types::ProgramExtents::none();
        NONE
    }

    fn name_at(&self, vaddr: u64) -> Option<String> {
        (vaddr == BASE).then(|| "caller".to_owned())
    }

    fn import_at(&self, _vaddr: u64) -> Option<String> {
        None
    }
}

#[test]
fn a_callee_whose_analysis_panics_is_unread_with_where_and_its_caller_renders() {
    // A panic reading one callee used to unwind through the caller and end
    // the session. It is a defect, so it is named -- where it was raised and
    // what it said -- and it stays with the callee.
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let prepared =
        r2engine::native::analysed(&target, &PanickingCallee, BASE).expect("the caller prepares");
    let [unread] = prepared.unread() else {
        panic!("one callee unread: {:?}", prepared.unread());
    };
    assert_eq!(unread.address, 0x100a);
    let r2engine::native::Unreadable::Panicked(panicked) = &unread.reason else {
        panic!("the callee panicked: {unread}");
    };
    assert_eq!(panicked.message, "a defect reading the callee at 0x100a");
    let location = panicked.location.as_ref().expect("the hook saw where");
    assert!(location.file.ends_with("native.rs"), "{location}");
    assert!(
        unread.to_string().starts_with(&format!(
            "0x100a: its analysis panicked at {location}: a defect reading"
        )),
        "{unread}"
    );
    let response = decompile(&target, &PanickingCallee, BASE).expect("the caller renders");
    assert!(
        response.output.text().contains("fcn_100a("),
        "{}",
        response.output
    );
}

/// The emission a response carries: the unit, its lines, its names.
fn emission(response: &r2engine::EngineDecompileResponse) -> &r2dec::Emission {
    match &response.output {
        r2engine::EngineRendering::Function(rendered) => rendered.emission(),
        r2engine::EngineRendering::Listing(text) => panic!("nothing rendered: {text}"),
    }
}

/// The instructions one line of a unit names, by the text on it.
fn named_by(emission: &r2dec::Emission, needle: &str) -> Vec<u64> {
    let line = emission
        .unit()
        .lines()
        .position(|line| line.contains(needle))
        .map(|index| index + 1)
        .unwrap_or_else(|| panic!("no line holds {needle}:\n{}", emission.unit()));
    emission
        .lines()
        .iter()
        .find(|entry| entry.line == line)
        .map(|entry| entry.addrs.clone())
        .unwrap_or_default()
}

/// Each line of the unit names the instructions it accounts for, only
/// instructions the function has, and every name outside the function is
/// linked to where it resolves.
///
/// `call 0x100a; ret`: the call statement is the call instruction's line and
/// the return is the `ret`'s. The callee is a function of the program at
/// 0x100a, and that address travels with its name.
#[test]
fn each_line_names_its_instructions_and_each_outside_name_its_address() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: CALLER.to_vec(),
        name: "caller",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let emission = emission(&response);
    let unit = emission.unit();

    assert!(
        named_by(emission, "fcn_100a((uint32_t)").contains(&0x1000),
        "{unit}"
    );
    assert!(named_by(emission, "return").contains(&0x1005), "{unit}");
    let lines = unit.lines().count();
    for line in emission.lines() {
        assert!((1..=lines).contains(&line.line), "{line:?}\n{unit}");
        assert!(
            line.addrs
                .iter()
                .all(|addr| [0x1000, 0x1005].contains(addr)),
            "{line:?} names an instruction the caller does not have:\n{unit}"
        );
    }

    let links = emission.links();
    assert_eq!(links.len(), 1, "{links:?}");
    assert_eq!(links[0].ident, "fcn_100a");
    assert_eq!(links[0].kind, r2dec::report::LinkKind::Function);
    assert_eq!(links[0].addr, Some(0x100a));

    let signature = emission.signature().expect("the unit defines the caller");
    assert!(signature.contains("caller("), "{signature}");
    assert!(unit.contains(signature), "{signature}\n{unit}");
    for variable in emission.variables() {
        assert!(unit.contains(&variable.name), "{variable:?}\n{unit}");
    }
}

#[test]
fn a_callee_that_returns_the_pushed_address_gives_its_caller_a_constant() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: PC_THUNK.to_vec(),
        name: "pc_caller",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");

    // The pushed address is the one after the call: 0x1005 + 0x10.
    assert!(
        response.output.text().contains("0x1015"),
        "the address the thunk's result names is not spelled: {}",
        response.output
    );
    // Spelled at its use, the call's own result binding has no reader left.
    assert!(
        !response.output.text().contains("RSI"),
        "the result binding outlived its readers: {}",
        response.output
    );
}

/// The slot a call pushes the return address into is not a local: nothing in
/// the program assigns it, and a rendering that declares one and then reads it
/// claims something the program does not.
#[test]
fn the_slot_the_caller_pushed_the_return_address_into_is_spelled() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: PC_THUNK.to_vec(),
        name: "pc_thunk",
    };
    // The thunk itself: `mov rsi, [rsp]; ret`, which reads what the call left.
    let response = decompile(&target, &program, BASE + 0x0b).expect("decompile");

    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{}",
        response.render_refusal,
        response.output
    );
    assert!(
        response
            .output
            .text()
            .contains("__builtin_return_address(0"),
        "the return address slot is not spelled: {}",
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

    fn region(&self, vaddr: u64) -> Option<r2ssa::body::Region> {
        code_region(CALLER.len(), vaddr)
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        matches!(vaddr, BASE | 0x100a)
    }
}

impl Program for Importing {
    fn holds_static_data(&self, _vaddr: u64) -> bool {
        false
    }

    /// Nothing here is loaded, so nothing is written by a loader.
    fn loader_writes(&self, _range: &std::ops::Range<u64>) -> bool {
        false
    }

    fn extents(&self) -> &r2types::ProgramExtents {
        const NONE: &r2types::ProgramExtents = &r2types::ProgramExtents::none();
        NONE
    }

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
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let response = decompile(&target, &Importing, BASE).expect("decompile");

    // strlen takes one argument, the convention says it arrives in rdi, and
    // the declaration says what it is.
    assert!(
        response.output.text().contains("strlen(const int8_t*)"),
        "{}",
        response.output
    );
    assert!(
        response
            .output
            .text()
            .contains("strlen((const int8_t*)RDI_0)"),
        "{}",
        response.output
    );
    // The same marker the plugin's route prints when radare2 supplies one.
    assert!(
        response
            .output
            .text()
            .contains("1 callee prototype supplied by the source"),
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
    let machine = Machine::new("aarch64", "aarch64", 64);
    // The stack pointer is the specification's to name on every machine.
    assert_eq!(machine.compiler.stack_pointer.as_deref(), Some("sp"));

    let target = machine.target();
    let program = Fixture {
        bytes: AARCH64_ADD_ONE.to_vec(),
        name: "add_one",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");

    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{}",
        response.render_refusal,
        response.output
    );
    assert!(
        response.output.text().contains("add_one("),
        "{}",
        response.output
    );
    assert!(
        response.output.text().contains("X0_0"),
        "{}",
        response.output
    );
    assert!(
        response.output.text().contains("return"),
        "{}",
        response.output
    );
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
    let machine = Machine::new("arm", "arm", 32);
    let target = machine.target();
    let program = Fixture {
        bytes: ARM_DEAD_LOAD.to_vec(),
        name: "dead_load",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");

    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{}",
        response.render_refusal,
        response.output
    );
    assert!(
        response.output.text().contains("(void)*"),
        "the discarded read is missing:\n{}",
        response.output
    );
}

/// The analysis tier can be asked for on its own, without asking for C.
///
/// A defect in the output is either already visible here or belongs to the
/// lowering below it, which is the whole reason the tier is printable.
#[test]
fn the_medium_tier_is_readable_without_rendering() {
    let machine = Machine::new("arm", "arm", 32);
    let target = machine.target();
    let program = Fixture {
        bytes: ARM_DEAD_LOAD.to_vec(),
        name: "dead_load",
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
    let machine = Machine::new("arm", "arm", 32);
    let target = machine.target();
    let program = Fixture {
        bytes: ARM_DEAD_LOAD.to_vec(),
        name: "dead_load",
    };
    let tree = r2engine::native::structured(&target, &program, BASE)
        .expect("structured")
        .output
        .into_text();
    let c = decompile(&target, &program, BASE)
        .expect("decompile")
        .output
        .into_text();

    assert!(tree.contains("Function: dead_load"), "{tree}");
    // The statements are spelled by the emitter that writes the C, so the two
    // tiers disagree about their shape and about nothing else.
    assert!(tree.contains("(void)*"), "{tree}");
    assert!(c.contains("(void)*"), "{c}");
}

/// The C tier hands back the tree it rendered, not only the text.
///
/// A consumer that wants to know what the function declares should walk it
/// rather than parse the C back, and the tree it walks has to be the one the
/// text was written from or the two can say different things.
#[test]
fn the_c_tier_hands_back_the_tree_the_text_came_from() {
    let machine = Machine::new("arm", "arm", 32);
    let target = machine.target();
    let program = Fixture {
        bytes: ARM_DEAD_LOAD.to_vec(),
        name: "dead_load",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let function = response
        .output
        .function()
        .expect("the C tier renders a function");
    assert_eq!(function.name, "dead_load");
    assert!(!function.body.is_empty(), "{:?}", function.body);
    // The text is what the emitter wrote from this tree, so the tree's name is
    // in it and nothing had a chance to substitute a different function.
    assert!(
        response.output.text().contains("dead_load"),
        "{}",
        response.output.text()
    );
}

#[test]
fn a_jump_table_is_read_out_of_the_program_and_rendered_as_a_switch() {
    // Nothing hands the engine this table: the guard bounds the index, the
    // value analysis says the dispatch reads four entries from 0x1030, and
    // the engine goes and reads them. Without that the walk stops at the
    // branch and the arms are never seen at all.
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: TABLE_SWITCH.to_vec(),
        name: "pick",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{}",
        response.render_refusal,
        response.output
    );
    let output = response.output.text();
    assert!(output.contains("switch ("), "{output}");
    // The `switch` is what the dispatch is: scaling the index, addressing the
    // table, reading the entry and branching through it are the statement, not
    // operations beside it that a marker has to stand in for.
    assert!(!output.contains("r2dec gap"), "{output}");
    assert!(!output.contains("residual"), "{output}");
    // Every arm, with the value the source case returned, in order.
    for (case, returns) in [(0, "10"), (1, "20"), (2, "30"), (3, "40")] {
        assert!(output.contains(&format!("case {case}:")), "{output}");
        assert!(output.contains(&format!("return {returns};")), "{output}");
    }
    let labels = output
        .match_indices("case ")
        .map(|(at, _)| at)
        .collect::<Vec<_>>();
    assert!(
        labels.windows(2).all(|pair| pair[0] < pair[1]),
        "the arms are written in label order: {output}"
    );
}

/// gcc -O0's `classify` without its spill: a relative jump table at `TABLE`
/// read through a 32-bit index nothing bounds, so the read reaches 2^32
/// entries -- 16 GiB -- of which the program maps sixteen bytes.
///
/// ```text
///   1000  mov  eax, edi              ; the index, zero-extended into rax
///   1002  lea  rdx, [rax*4]
///   100a  lea  rax, [rip + 0xfef]    ; TABLE
///   1011  mov  eax, [rdx + rax]      ; one entry
///   1014  cdqe
///   1016  lea  rdx, [rip + 0xfe3]    ; TABLE again, the base the entry is relative to
///   101d  add  rax, rdx
///   1020  jmp  rax
/// ```
const UNBOUNDED_TABLE: &[u8] = &[
    0x89, 0xf8, // 1000 mov eax, edi
    0x48, 0x8d, 0x14, 0x85, 0x00, 0x00, 0x00, 0x00, // 1002 lea rdx, [rax*4]
    0x48, 0x8d, 0x05, 0xef, 0x0f, 0x00, 0x00, // 100a lea rax, [rip + 0xfef]
    0x8b, 0x04, 0x02, // 1011 mov eax, [rdx + rax]
    0x48, 0x98, // 1014 cdqe
    0x48, 0x8d, 0x15, 0xe3, 0x0f, 0x00, 0x00, // 1016 lea rdx, [rip + 0xfe3]
    0x48, 0x01, 0xd0, // 101d add rax, rdx
    0xff, 0xe0, // 1020 jmp rax
];
/// Where that table lies: sixteen bytes of read-only data.
const TABLE: u64 = 0x2000;
const TABLE_BYTES: [u8; 16] = [0; 16];

/// `UNBOUNDED_TABLE` as code and `TABLE` as data, and every read anyone made of either.
#[derive(Default)]
struct Unbounded {
    reads: std::cell::RefCell<Vec<std::ops::Range<u64>>>,
    /// How far past the sixteen bytes the file holds the container says the
    /// table's segment runs, all of it zeros the loader fills.
    zero_filled: u64,
}

impl Unbounded {
    /// Every read that asked for a byte of the table's segment.
    fn table_reads(&self) -> Vec<std::ops::Range<u64>> {
        let end = TABLE + 16 + self.zero_filled;
        let reads = self.reads.borrow();
        let touched = reads
            .iter()
            .filter(|read| read.start < end && TABLE < read.end);
        touched.cloned().collect()
    }
}

impl r2ssa::body::Program for Unbounded {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let region = self.region(vaddr)?;
        let bytes: &[u8] = match region.execute {
            true => UNBOUNDED_TABLE,
            false => &TABLE_BYTES,
        };
        // What was asked for is recorded, whatever is answered. Past what the
        // file holds this answers nothing rather than allocating the zeros,
        // so the old read runs out of bytes here and not out of memory.
        self.reads
            .borrow_mut()
            .push(vaddr..vaddr.saturating_add(max as u64));
        let rest = bytes.get(usize::try_from(vaddr - region.start).ok()?..)?;
        Some(rest[..rest.len().min(max)].to_vec())
    }

    fn region(&self, vaddr: u64) -> Option<r2ssa::body::Region> {
        let code = code_region(UNBOUNDED_TABLE.len(), vaddr);
        let end = TABLE + 16 + self.zero_filled;
        let table = (TABLE..end)
            .contains(&vaddr)
            .then_some(r2ssa::body::Region {
                start: TABLE,
                end,
                file_end: TABLE + 16,
                execute: false,
                write: false,
            });
        code.or(table)
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        vaddr == BASE
    }
}

impl Program for Unbounded {
    fn holds_static_data(&self, _vaddr: u64) -> bool {
        false
    }

    fn loader_writes(&self, _range: &std::ops::Range<u64>) -> bool {
        false
    }

    fn extents(&self) -> &r2types::ProgramExtents {
        const NONE: &r2types::ProgramExtents = &r2types::ProgramExtents::none();
        NONE
    }

    fn name_at(&self, vaddr: u64) -> Option<String> {
        (vaddr == BASE).then(|| "classify".to_owned())
    }

    fn import_at(&self, _vaddr: u64) -> Option<String> {
        None
    }
}

#[test]
fn a_table_longer_than_the_region_it_starts_in_is_refused_before_a_byte_of_it_is_read() {
    // The read is sound -- the index does reach every 32-bit value -- and
    // what refuses it is that the program has sixteen bytes there, not 16
    // GiB. The old read built a label per entry first and ran out of memory.
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Unbounded::default();
    let prepared = r2engine::native::analysed(&target, &program, BASE).expect("analysed");
    let reads =
        r2ssa::indirect::dispatch_table_reads(prepared.artifact().shared_artifact().as_ref());
    assert_eq!(
        reads
            .iter()
            .map(|read| (read.address, read.count, read.span()))
            .collect::<Vec<_>>(),
        vec![(TABLE, 1 << 32, Some(1 << 34))],
        "the value analysis states the whole reach"
    );
    let touched = program.table_reads();
    assert!(touched.is_empty(), "the table was read: {touched:?}");
    unresolved_at_the_dispatch(&prepared);
}

/// Refused, so the dispatch is where the walk stops rather than a guess.
fn unresolved_at_the_dispatch(prepared: &r2engine::native::Prepared) {
    assert!(prepared.table_at(0x1020).is_none());
    assert_eq!(
        prepared
            .body()
            .unresolved
            .iter()
            .map(|stop| (stop.addr, stop.reason))
            .collect::<Vec<_>>(),
        vec![(0x1020, r2ssa::body::UnresolvedReason::IndirectBranch)]
    );
}

#[test]
fn a_table_running_into_bytes_the_loader_zero_fills_is_refused_before_a_byte_of_it_is_read() {
    // A container may state a segment far longer than the file holds -- a
    // large `.bss` after `.data`, or a header that simply claims it -- and
    // reading there answers zeros the image allocates. Bounded by the
    // segment alone, the same spilled index asked for 16 GiB of them. Zeros
    // the loader fills are bytes it writes, so the file states none of the
    // table and nothing past its sixteen bytes is asked for.
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Unbounded {
        zero_filled: 1 << 40,
        ..Unbounded::default()
    };
    let prepared = r2engine::native::analysed(&target, &program, BASE).expect("analysed");
    let touched = program.table_reads();
    assert!(touched.is_empty(), "the table was read: {touched:?}");
    unresolved_at_the_dispatch(&prepared);
}

#[test]
fn an_indirect_branch_the_walk_could_not_follow_is_no_tail_call() {
    // The dispatch is where the walk stopped, so the block names no successor
    // because none is known. Read as "control leaves here", it rendered as
    // `return ((int32_t(*)(void))*(...))();` with nothing refused: a tail
    // call the program never makes, in place of the switch it does.
    let machine = Machine::new("x86-64", "x86-64", 64);
    let response = decompile(&machine.target(), &Unbounded::default(), BASE).expect("decompile");
    let output = response.output.text();
    assert!(response.render_refusal.is_some(), "{output}");
    assert!(!output.contains(")()"), "{output}");
    assert!(!output.contains("return (("), "{output}");
}

#[test]
fn what_a_function_returns_is_read_off_the_arms_its_dispatch_reaches() {
    // The first walk stops at the dispatch and sees no return; that is no proof the result is void.
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: SPILLED_SWITCH.to_vec(),
        name: "pick",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let output = response.output.text();
    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{output}",
        response.render_refusal
    );
    assert!(!output.starts_with("void "), "{output}");
    for returns in ["10", "20", "30"] {
        assert!(output.contains(&format!("return {returns};")), "{output}");
    }
}

#[test]
fn a_machine_operation_the_specification_names_is_called_and_declared() {
    // A barrier has no C spelling and Sleigh gives it none either: it arrives
    // as a user operation with an index. The index names an operation in the
    // specification, and saying that is both more than refusing the function
    // said and less than claiming an ordering the operand was never read for.
    const BARRIER: &[u8] = &[
        0x10, 0x40, 0x2d, 0xe9, // push {r4, lr}
        0x5f, 0xf0, 0x7f, 0xf5, // dmb sy
        0x10, 0x80, 0xbd, 0xe8, // pop {r4, pc}
    ];
    let machine = Machine::new("arm", "arm", 32);
    let target = machine.target();
    let program = Fixture {
        bytes: BARRIER.to_vec(),
        name: "barrier",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let output = response.output.text();
    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{output}",
        response.render_refusal
    );
    // Called by the name the specification gives it, and declared, so the
    // rendering still compiles.
    assert!(output.contains("DataMemoryBarrier("), "{output}");
    assert!(output.contains("void DataMemoryBarrier("), "{output}");
}

#[test]
fn an_exclusive_pair_reaches_the_rendering_rather_than_the_projection() {
    // `ldrex`/`strex` are a linked read and a conditional store, and the
    // machine model states both exactly. Before it did, the projection could
    // not describe either and every function using them refused there --
    // which is every C++ atomic on this architecture.
    const ATOMIC_INCREMENT: &[u8] = &[
        0x10, 0xb5, // push {r4, lr}
        0x51, 0xe8, 0x00, 0x2f, // ldrex r2, [r1, 0]
        0x01, 0x32, // adds r2, 1
        0x41, 0xe8, 0x00, 0x23, // strex r3, r2, [r1, 0]
        0x10, 0xbd, // pop {r4, pc}
    ];
    let machine = Machine::new("thumb", "arm", 32);
    let target = machine.target();
    let program = Fixture {
        bytes: ATOMIC_INCREMENT.to_vec(),
        name: "increment",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    assert!(
        !format!("{:?}", response.render_refusal).contains("MachineProjection"),
        "{:?}\n{}",
        response.render_refusal,
        response.output
    );
    assert!(
        response.output.text().contains("store_conditional")
            || response.output.text().contains("load_linked"),
        "{}",
        response.output
    );
}

#[test]
fn a_barrier_writes_no_register_so_the_value_before_it_is_returned() {
    // `dmb` is a user operation with no output, and p-code says it writes nothing else.
    const BARRIER_LEAF: &[u8] = &[
        0x07, 0x00, 0xa0, 0xe3, // mov r0, 7
        0x5f, 0xf0, 0x7f, 0xf5, // dmb sy
        0x1e, 0xff, 0x2f, 0xe1, // bx lr
    ];
    let machine = Machine::new("arm", "arm", 32);
    let target = machine.target();
    let program = Fixture {
        bytes: BARRIER_LEAF.to_vec(),
        name: "order",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let output = response.output.text();
    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{output}",
        response.render_refusal
    );
    assert!(output.contains("DataMemoryBarrier("), "{output}");
    assert!(output.contains("return 7;"), "{output}");
    assert!(!output.contains("r2dec gap"), "{output}");
}

/// Whether a rendering marks its return as unproven: the header declares the
/// result carrier a caller reads, and the return hands back a residual of it,
/// which traps if it is ever reached. Nothing else in the text claims a value.
fn marks_an_unproven_return(output: &str) -> bool {
    output.starts_with("uint64_t ") && output.contains("return r2sleigh_residual_u64(")
}

#[test]
fn a_system_call_leaves_the_return_a_marked_gap_and_the_function_still_renders() {
    // The kernel writes x0 and no declared contract says so, so the result is neither `void` nor the value before the call.
    const EXIT: &[u8] = &[
        0x00, 0x00, 0x80, 0xd2, // mov x0, 0
        0xa8, 0x0b, 0x80, 0xd2, // mov x8, 93
        0x01, 0x00, 0x00, 0xd4, // svc 0
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ];
    let machine = Machine::new("aarch64", "aarch64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: EXIT.to_vec(),
        name: "start",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let output = response.output.text();
    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{output}",
        response.render_refusal
    );
    assert!(output.contains("CallSupervisor("), "{output}");
    assert!(marks_an_unproven_return(output), "{output}");
    assert!(!output.contains("return 0;"), "{output}");
}

#[test]
fn an_untouched_result_register_is_unproven_where_it_is_also_the_first_argument() {
    // On AArch64 x0 is arg1 and the result: leaving it alone may be returning it.
    const READ_ONLY: &[u8] = &[
        0x01, 0x00, 0x40, 0xb9, // ldr w1, [x0]
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ];
    let machine = Machine::new("aarch64", "aarch64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: READ_ONLY.to_vec(),
        name: "touch",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let output = response.output.text();
    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{output}",
        response.render_refusal
    );
    assert!(marks_an_unproven_return(output), "{output}");

    // On x86-64 rax is no argument, so a caller never filled it and nothing is returned.
    const STORE: &[u8] = &[
        0xc7, 0x07, 0x01, 0x00, 0x00, 0x00, // mov dword [rdi], 1
        0xc3, // ret
    ];
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: STORE.to_vec(),
        name: "store",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let output = response.output.text();
    assert!(output.starts_with("void store("), "{output}");
}

/// `lea rax, [rbx + rsi]; ret`: one register the function entered holding, and
/// one argument slot whose parameter recovery does not admit, because the slot
/// before it is never read.
const ENTRY_AND_ARGUMENT: &[u8] = &[
    0x48, 0x8d, 0x04, 0x33, // 1000 lea rax, [rbx + rsi]
    0xc3, // 1004 ret
];

/// A read of a value nothing in the body assigns is accounted by name, and the
/// two kinds are kept apart.
///
/// The proof line used to give a count of values held from entry. The count
/// included the return-address slot, which the body never spells, and it
/// excluded an argument slot on purpose. The certification gate took the count
/// as how many unassigned reads to skip, so here it skipped both `RBX_0` and
/// `RSI_0`, and an argument read with no parameter passed as certified.
#[test]
fn a_value_no_statement_assigns_is_named_on_the_proof_line() {
    let text = rendered(ENTRY_AND_ARGUMENT, "entry_and_argument");
    let proof = text
        .lines()
        .find(|line| line.contains("r2dec proof:"))
        .unwrap_or_else(|| panic!("no proof line: {text}"));
    // rbx is not an argument slot, and the function never assigns it: that is
    // what held from entry means, and only that. C has no spelling for such a
    // value, so the read is a residual rather than an indeterminate object.
    assert!(
        proof.contains("; 1 held from entry, read as residuals (RBX_0)"),
        "{text}"
    );
    // rsi is an argument slot with no parameter, so the rendering reads a value
    // its own signature says it was never given. It is not excused as held.
    assert!(
        proof.contains("; 1 argument slot read with no parameter, read as residuals (RSI_0)"),
        "{text}"
    );
    // Neither is declared as an object nothing assigns: each read traps.
    assert!(!text.contains("uint64_t RSI_0;"), "{text}");
    assert!(!text.contains("uint64_t RBX_0;"), "{text}");
    assert_eq!(text.matches("r2sleigh_residual_u64(").count(), 2, "{text}");

    // The first stack argument is an argument slot too: above the return
    // address, where the caller placed it. It was counted as held from entry.
    let text = rendered(STACK_ARGUMENT, "stack_argument");
    let proof = text
        .lines()
        .find(|line| line.contains("r2dec proof:"))
        .unwrap_or_else(|| panic!("no proof line: {text}"));
    assert!(
        proof.contains("; 1 argument slot read with no parameter, read as residuals (stack_p8)"),
        "{text}"
    );
    assert!(!proof.contains("held from entry"), "{text}");
}

/// `mov rax, [rsp + 8]; ret`: the first stack argument, with no register
/// argument before it that recovery would admit.
const STACK_ARGUMENT: &[u8] = &[
    0x48, 0x8b, 0x44, 0x24, 0x08, // 1000 mov rax, [rsp + 8]
    0xc3, // 1005 ret
];

/// A loop entered at two blocks, whose counter climbs on every pass.
///
/// ```text
///   1000  xor eax, eax
///   1002  test edi, edi
///   1004  je  0x100c        ; enter the loop at its second block
///   1006  inc eax           ; first block
///   1008  cmp eax, esi
///   100a  jae 0x1012
///   100c  inc eax           ; second block
///   100e  cmp eax, esi
///   1010  jb  0x1006
///   1012  ret
/// ```
const IRREDUCIBLE_COUNTER: &[u8] = &[
    0x31, 0xc0, // 1000 xor eax, eax
    0x85, 0xff, // 1002 test edi, edi
    0x74, 0x06, // 1004 je 0x100c
    0xff, 0xc0, // 1006 inc eax
    0x39, 0xf0, // 1008 cmp eax, esi
    0x73, 0x06, // 100a jae 0x1012
    0xff, 0xc0, // 100c inc eax
    0x39, 0xf0, // 100e cmp eax, esi
    0x72, 0xf4, // 1010 jb 0x1006
    0xc3, // 1012 ret
];

/// Neither block of the loop dominates the other, so it has no natural header;
/// the value fixpoint still has to widen on it or it climbs one step per round.
#[test]
fn a_loop_with_two_entries_is_decompiled_in_bounded_time() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: IRREDUCIBLE_COUNTER.to_vec(),
        name: "count",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    assert!(
        response.render_refusal.is_none() && response.output.text().contains("return"),
        "{:?}\n{}",
        response.render_refusal,
        response.output
    );
}

/// xor eax, eax; or rcx, -1; repne scasb; not rcx; lea rax, [rcx - 1]; ret
///
/// The inline `strlen` older compilers emit: the scan repeats its own
/// instruction until it finds the byte or runs out of count.
const REPEATED_SCAN: &[u8] = &[
    0x31, 0xc0, // 0x1000 xor eax, eax
    0x48, 0x83, 0xc9, 0xff, // 0x1002 or rcx, -1
    0xf2, 0xae, // 0x1006 repne scasb
    0x48, 0xf7, 0xd1, // 0x1008 not rcx
    0x48, 0x8d, 0x41, 0xff, // 0x100b lea rax, [rcx - 1]
    0xc3, // 0x100f ret
];

/// The inline `memcmp` sign, read from the flags of the last pair compared.
const REPEATED_COMPARE: &[u8] = &[
    0x31, 0xc0, // 0x1000 xor eax, eax
    0x48, 0x89, 0xd1, // 0x1002 mov rcx, rdx
    0xf3, 0xa6, // 0x1005 repe cmpsb
    0x0f, 0x97, 0xc0, // 0x1007 seta al
    0x1c, 0x00, // 0x100a sbb al, 0
    0x0f, 0xbe, 0xc0, // 0x100c movsx eax, al
    0xc3, // 0x100f ret
];

/// Render x86-64 bytes mapped at `BASE`, refusing nothing.
fn rendered(bytes: &'static [u8], name: &'static str) -> String {
    rendered_on(&Machine::new("x86-64", "x86-64", 64), bytes, name)
}

/// Render bytes of `machine` mapped at `BASE`, refusing nothing.
fn rendered_on(machine: &Machine, bytes: &'static [u8], name: &'static str) -> String {
    let target = machine.target();
    let program = Fixture {
        bytes: bytes.to_vec(),
        name,
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let text = response.output.text().to_string();
    assert!(response.render_refusal.is_none(), "{text}");
    text
}

/// Compile the rendered function under a C harness and run it; the harness exits zero when every check holds.
///
/// A rendering that never returns is as wrong as one that returns the wrong
/// value, so the harness is killed by `SIGALRM` if it is still running after
/// thirty seconds, and the check fails instead of hanging the suite.
fn run_rendered(name: &str, function: &str, harness: &str) {
    let dir = std::env::temp_dir().join(format!("r2engine-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    let source = dir.join("rendered.c");
    let binary = dir.join("rendered");
    std::fs::write(
        &source,
        format!(
            "#define _POSIX_C_SOURCE 200809L\n#include <stdint.h>\n#include <string.h>\n\
             #include <unistd.h>\n\
             __attribute__((constructor)) static void r2engine_watchdog(void) {{ alarm(30); }}\n\
             {function}\n{harness}\n"
        ),
    )
    .expect("write the rendering");
    let compiled = std::process::Command::new("cc")
        .args(["-std=c11", "-w", "-o"])
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("a C compiler");
    assert!(
        compiled.status.success(),
        "{}\n{function}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let ran = std::process::Command::new(&binary)
        .status()
        .expect("run the rendering");
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(
        ran.code(),
        Some(0),
        "check {:?} failed:\n{function}",
        ran.code()
    );
}

/// A repeated scan renders as the walk it is, and the walk is `strlen`.
#[test]
fn a_repeated_scan_renders_as_the_walk_it_is() {
    let text = rendered(REPEATED_SCAN, "scan");
    assert!(text.contains("while (reached != "), "{text}");
    assert!(text.contains("break;"), "{text}");
    run_rendered(
        "scan",
        &text,
        r#"int main(void) {
    const char *words[] = {"", "a", "hello", "bash"};
    for (int i = 0; i < 4; i++) {
        if (scan((uint64_t)(uintptr_t)words[i]) != strlen(words[i])) {
            return 1 + i;
        }
    }
    return 0;
}"#,
    );
}

/// A repeated compare leaves the flags of its last pair, or of the `xor` where the count is zero.
#[test]
fn a_repeated_compare_leaves_the_flags_of_its_last_pair() {
    let text = rendered(REPEATED_COMPARE, "compare");
    assert!(text.contains("if (other != element)"), "{text}");
    run_rendered(
        "compare",
        &text,
        r#"static int sign(int value) { return (value > 0) - (value < 0); }
int main(void) {
    const struct { const char *dst, *src; uint64_t n; } cases[] = {
        {"abc", "abc", 3}, {"abc", "abd", 3}, {"abd", "abc", 3}, {"abc", "xyz", 0},
        {"\x80", "\x01", 1}, {"xa", "ya", 2}, {"ab", "ab", 1},
    };
    for (int i = 0; i < 7; i++) {
        int want = sign(memcmp(cases[i].src, cases[i].dst, cases[i].n));
        int got = (int32_t)compare((uint64_t)(uintptr_t)cases[i].dst,
                                   (uint64_t)(uintptr_t)cases[i].src, cases[i].n);
        if (got != want) {
            return 1 + i;
        }
    }
    return 0;
}"#,
    );
}

/// A loop whose header is the function's entry: control reaches the first
/// instruction both from the caller and from the latch.
const ENTRY_LOOP: &[u8] = &[
    0x48, 0x01, 0xfe, // 0x1000 add rsi, rdi
    0x48, 0xff, 0xcf, // 0x1003 dec rdi
    0x75, 0xf8, // 0x1006 jnz 0x1000
    0x48, 0x89, 0xf0, // 0x1008 mov rax, rsi
    0xc3, // 0x100b ret
];

/// The entry is a loop header with two latches, one of which also counts.
const ENTRY_LOOP_TWO_LATCHES: &[u8] = &[
    0x48, 0x85, 0xff, // 0x1000 test rdi, rdi
    0x74, 0x0d, // 0x1003 je 0x1012
    0x48, 0xff, 0xcf, // 0x1005 dec rdi
    0x48, 0x85, 0xf6, // 0x1008 test rsi, rsi
    0x74, 0xf3, // 0x100b je 0x1000
    0x48, 0xff, 0xc2, // 0x100d inc rdx
    0xeb, 0xee, // 0x1010 jmp 0x1000
    0x48, 0x89, 0xd0, // 0x1012 mov rax, rdx
    0xc3, // 0x1015 ret
];

/// `shape_mutual_even` and `shape_mutual_odd` of `tests/corpus/shapes.c` as
/// GCC -O2 compiles them, each tail-jumping to the other; only `even` is a
/// declared entry, so its body takes in `odd` and the jump back to the entry
/// closes a loop.
const MUTUAL_TAIL_RECURSION: &[u8] = &[
    0x48, 0x85, 0xff, // 0x1000 even: test rdi, rdi
    0x75, 0x09, // 0x1003 jne 0x100e
    0xb8, 0xa5, 0xa5, 0xa5, 0xa5, // 0x1005 mov eax, 0xa5a5a5a5
    0x48, 0x31, 0xf0, // 0x100a xor rax, rsi
    0xc3, // 0x100d ret
    0x48, 0x89, 0xf0, // 0x100e mov rax, rsi
    0x48, 0xc1, 0xe0, 0x05, // 0x1011 shl rax, 5
    0x48, 0x29, 0xf0, // 0x1015 sub rax, rsi
    0x48, 0x8d, 0x34, 0x38, // 0x1018 lea rsi, [rax + rdi]
    0x48, 0x83, 0xef, 0x01, // 0x101c sub rdi, 1
    0xeb, 0x00, // 0x1020 jmp odd
    0x48, 0x89, 0xf0, // 0x1022 odd: mov rax, rsi
    0x48, 0x85, 0xff, // 0x1025 test rdi, rdi
    0x75, 0x07, // 0x1028 jne 0x1031
    0x48, 0x35, 0x5a, 0x5a, 0x5a, 0x5a, // 0x102a xor rax, 0x5a5a5a5a
    0xc3, // 0x1030 ret
    0x48, 0xc1, 0xe0, 0x04, // 0x1031 shl rax, 4
    0x48, 0x01, 0xf0, // 0x1035 add rax, rsi
    0x48, 0x8d, 0x34, 0xb8, // 0x1038 lea rsi, [rax + rdi*4]
    0x48, 0x83, 0xef, 0x01, // 0x103c sub rdi, 1
    0xeb, 0xbe, // 0x1040 jmp even
];

/// The first pass of a loop at the entry reads what the caller passed, and
/// every later pass what the latch left: the latch's decrement is observed.
#[test]
fn a_loop_at_the_entry_carries_what_its_latch_writes() {
    let text = rendered(ENTRY_LOOP, "entry_loop");
    run_rendered(
        "entry_loop",
        &text,
        r#"int main(void) {
    const uint64_t n[] = {1, 2, 5, 10, 3};
    const uint64_t acc[] = {0, 0, 0, 7, 100};
    for (int i = 0; i < 5; i++) {
        if (entry_loop(n[i], acc[i]) != acc[i] + n[i] * (n[i] + 1) / 2) {
            return 1 + i;
        }
    }
    return 0;
}"#,
    );
}

/// Two latches and the caller all reach the entry, so each merge there has
/// three ways in, and the one from the caller is the argument.
#[test]
fn an_entry_with_two_latches_merges_the_caller_and_both_latches() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: ENTRY_LOOP_TWO_LATCHES.to_vec(),
        name: "two_latches",
    };
    let prepared = r2engine::native::prepared(&target, &program, BASE).expect("prepared");
    let artifact = prepared.artifact();
    let graph = artifact.graph();
    let header = graph
        .block_id_for_addr(BASE)
        .and_then(|id| graph.block(id))
        .expect("the entry block");
    let dump = artifact.function().dump();
    assert_eq!(header.predecessors.len(), 3, "{dump}");
    // The counter is written on one latch only, so its merge is the one
    // that has to take the caller's value, the counting latch's and the
    // other latch's.
    let merges_the_caller = header.insts.iter().any(|inst| {
        let inst = graph.inst(*inst).expect("an instruction of the block");
        matches!(&inst.payload, InstPayload::Phi { predecessors } if predecessors.len() == 3)
            && inst
                .inputs
                .iter()
                .any(|input| graph.caller_supplied(*input))
    });
    assert!(
        merges_the_caller,
        "no merge at the entry takes the caller's value:\n{dump}"
    );

    let text = rendered(ENTRY_LOOP_TWO_LATCHES, "two_latches");
    run_rendered(
        "two_latches",
        &text,
        r#"int main(void) {
    const uint64_t n[] = {0, 1, 4, 4, 9};
    const uint64_t flag[] = {1, 1, 1, 0, 3};
    const uint64_t acc[] = {5, 0, 10, 10, 1};
    for (int i = 0; i < 5; i++) {
        uint64_t want = acc[i] + (flag[i] != 0 ? n[i] : 0);
        if (two_latches(n[i], flag[i], acc[i]) != want) {
            return 1 + i;
        }
    }
    return 0;
}"#,
    );
}

/// Mutual tail recursion walked into one body is a loop through the entry,
/// and each pass takes both partners' steps.
#[test]
fn mutual_tail_recursion_takes_both_partners_steps() {
    let text = rendered(MUTUAL_TAIL_RECURSION, "mutual_even");
    run_rendered(
        "mutual_even",
        &text,
        r#"static uint64_t ref_odd(uint64_t depth, uint64_t accumulator);
static uint64_t ref_even(uint64_t depth, uint64_t accumulator) {
    return depth == 0 ? accumulator ^ 0xa5a5a5a5u : ref_odd(depth - 1u, accumulator * 31u + depth);
}
static uint64_t ref_odd(uint64_t depth, uint64_t accumulator) {
    return depth == 0 ? accumulator ^ 0x5a5a5a5au : ref_even(depth - 1u, accumulator * 17u + (depth << 2));
}
int main(void) {
    for (uint64_t depth = 0; depth < 12; depth++) {
        const uint64_t accumulator = 0x0123456789abcdefULL ^ (depth * 0x9e3779b97f4a7c15ULL);
        if (mutual_even(depth, accumulator) != ref_even(depth, accumulator)) {
            return 1 + (int)depth;
        }
    }
    return 0;
}"#,
    );
}

/// mov rax, rdi; and rax, -2; ret
///
/// The constant clears one bit and keeps some bit of every byte, so every
/// byte of the argument reaches the result.
const CLEAR_LOW_BIT: &[u8] = &[
    0x48, 0x89, 0xf8, // 0x1000 mov rax, rdi
    0x48, 0x83, 0xe0, 0xfe, // 0x1003 and rax, -2
    0xc3, // 0x1007 ret
];

/// An `and` that clears one bit reads the whole argument, not its low byte.
#[test]
fn an_and_that_clears_one_bit_takes_the_whole_argument() {
    let text = rendered(CLEAR_LOW_BIT, "clear_low_bit");
    assert!(
        text.starts_with("uint64_t clear_low_bit(uint64_t "),
        "{text}"
    );
    run_rendered(
        "clear_low_bit",
        &text,
        r#"int main(void) {
    const uint64_t cases[] = {
        0x1234567890abcdefULL, 0, 1, 0xffffffffffffffffULL, 0x8000000000000001ULL,
    };
    for (int i = 0; i < 5; i++) {
        if (clear_low_bit(cases[i]) != (cases[i] & ~(uint64_t)1)) {
            return 1 + i;
        }
    }
    return 0;
}"#,
    );
}

/// mov eax, edi; and eax, 0xffffff; ret
const MASK_24_OF_EDI: &[u8] = &[
    0x89, 0xf8, // 0x1000 mov eax, edi
    0x25, 0xff, 0xff, 0xff, 0x00, // 0x1002 and eax, 0xffffff
    0xc3, // 0x1007 ret
];

/// mov rax, rdi; and rax, 0xffffff; ret
const MASK_24_OF_RDI: &[u8] = &[
    0x48, 0x89, 0xf8, // 0x1000 mov rax, rdi
    0x48, 0x25, 0xff, 0xff, 0xff, 0x00, // 0x1003 and rax, 0xffffff
    0xc3, // 0x1009 ret
];

/// and w0, w0, #0xffffff; ret
const AARCH64_MASK_24_OF_W0: &[u8] = &[
    0x00, 0x5c, 0x00, 0x12, // 0x1000 and w0, w0, #0xffffff
    0xc0, 0x03, 0x5f, 0xd6, // 0x1004 ret
];

/// An `and` that keeps three bytes reads three bytes of the argument, and
/// no register has a three-byte lane, so the formal is the four-byte one
/// that holds them rather than a width no interface can carry.
#[test]
fn an_and_that_keeps_three_bytes_takes_the_four_byte_lane() {
    let text = rendered(MASK_24_OF_EDI, "mask24_of_edi");
    assert!(
        text.starts_with("uint32_t mask24_of_edi(uint32_t "),
        "{text}"
    );
    run_rendered(
        "mask24_of_edi",
        &text,
        r#"int main(void) {
    if (mask24_of_edi(0xabcdef12u) != 0xcdef12u) {
        return 1;
    }
    if (mask24_of_edi(0xffffffffu) != 0xffffffu) {
        return 2;
    }
    if (mask24_of_edi(0) != 0) {
        return 3;
    }
    return 0;
}"#,
    );

    let text = rendered(MASK_24_OF_RDI, "mask24_of_rdi");
    assert!(
        text.starts_with("uint64_t mask24_of_rdi(uint32_t "),
        "{text}"
    );
    run_rendered(
        "mask24_of_rdi",
        &text,
        r#"int main(void) {
    const uint64_t cases[] = {
        0xffffffffffffffffULL, 0x1234567890abcdefULL, 0xabcdef12ULL, 0, 0x80000000ff000000ULL,
    };
    for (int i = 0; i < 5; i++) {
        if (mask24_of_rdi(cases[i]) != (cases[i] & 0xffffff)) {
            return 1 + i;
        }
    }
    return 0;
}"#,
    );

    let text = rendered_on(
        &Machine::new("aarch64", "aarch64", 64),
        AARCH64_MASK_24_OF_W0,
        "mask24_of_w0",
    );
    assert!(
        text.starts_with("uint32_t mask24_of_w0(uint32_t "),
        "{text}"
    );
    run_rendered(
        "mask24_of_w0",
        &text,
        r#"int main(void) {
    if (mask24_of_w0(0xabcdef12u) != 0xcdef12u) {
        return 1;
    }
    if (mask24_of_w0(0xffffffffu) != 0xffffffu) {
        return 2;
    }
    return 0;
}"#,
    );
}

/// and x0, x0, #0xffffffffffff; ret
const AARCH64_MASK_48: &[u8] = &[
    0x00, 0xbc, 0x40, 0x92, // 0x1000 and x0, x0, #0xffffffffffff
    0xc0, 0x03, 0x5f, 0xd6, // 0x1004 ret
];

/// and x0, x0, #0xffffffffffffff; ret -- the top-byte-ignore untag.
const AARCH64_MASK_56: &[u8] = &[
    0x00, 0xdc, 0x40, 0x92, // 0x1000 and x0, x0, #0xffffffffffffff
    0xc0, 0x03, 0x5f, 0xd6, // 0x1004 ret
];

/// An `and` that keeps six or seven bytes of a 64-bit register reads more
/// than any narrower lane holds, so the formal is the whole register.
#[test]
fn an_and_that_keeps_six_or_seven_bytes_takes_the_whole_register() {
    let machine = Machine::new("aarch64", "aarch64", 64);
    for (bytes, name, kept) in [
        (AARCH64_MASK_48, "mask48", "0xffffffffffffULL"),
        (AARCH64_MASK_56, "untag56", "0xffffffffffffffULL"),
    ] {
        let text = rendered_on(&machine, bytes, name);
        assert!(
            text.starts_with(&format!("uint64_t {name}(uint64_t ")),
            "{text}"
        );
        run_rendered(
            name,
            &text,
            &format!(
                r#"int main(void) {{
    const uint64_t cases[] = {{
        0xabcd123456789abcULL, 0xffffffffffffffffULL, 0x8000000000000001ULL, 0,
    }};
    for (int i = 0; i < 4; i++) {{
        if ({name}(cases[i]) != (cases[i] & {kept})) {{
            return 1 + i;
        }}
    }}
    return 0;
}}"#
            ),
        );
    }
}

/// The argument copied into both halves of a vector and read back out of
/// the high one, which starts at the vector's eighth byte.
///
/// ```text
///   1000  movq    xmm0, rdi
///   1005  pshufd  xmm0, xmm0, 0x44
///   100a  movhlps xmm0, xmm0
///   100d  movq    rax, xmm0
///   1012  ret
/// ```
const HIGH_QWORD: &[u8] = &[
    0x66, 0x48, 0x0f, 0x6e, 0xc7, // 1000 movq xmm0, rdi
    0x66, 0x0f, 0x70, 0xc0, 0x44, // 1005 pshufd xmm0, xmm0, 0x44
    0x0f, 0x12, 0xc0, // 100a movhlps xmm0, xmm0
    0x66, 0x48, 0x0f, 0x7e, 0xc0, // 100d movq rax, xmm0
    0xc3, // 1012 ret
];

/// A read of a vector's high half observes the argument that filled it, so
/// the argument is a parameter rather than a local nothing assigns.
#[test]
fn an_argument_read_back_from_the_high_half_of_a_vector_is_a_parameter() {
    let text = rendered(HIGH_QWORD, "high_qword");
    assert!(text.starts_with("uint64_t high_qword(uint64_t "), "{text}");
    run_rendered(
        "high_qword",
        &text,
        r#"int main(void) {
    const uint64_t cases[] = {
        0x1234567890abcdefULL, 0, 1, 0xffffffffffffffffULL, 0x8000000000000001ULL,
    };
    for (int i = 0; i < 5; i++) {
        if (high_qword(cases[i]) != cases[i]) {
            return 1 + i;
        }
    }
    return 0;
}"#,
    );
}

/// `pmovsxbd xmm0, [rdi]`, stored a quadword at a time, returning zero.
///
/// ```text
///   1000  pmovsxbd xmm0, dword [rdi]
///   1005  movq     qword [rsi], xmm0
///   1009  movhps   qword [rsi + 8], xmm0
///   100d  xor      eax, eax
///   100f  ret
/// ```
///
/// `eax` is the result so that the vector register is not mistaken for one.
const PACKED_SIGN_EXTEND: &[u8] = &[
    0x66, 0x0f, 0x38, 0x21, 0x07, // 1000 pmovsxbd xmm0, dword [rdi]
    0x66, 0x0f, 0xd6, 0x06, // 1005 movq qword [rsi], xmm0
    0x0f, 0x17, 0x46, 0x08, // 1009 movhps qword [rsi + 8], xmm0
    0x31, 0xc0, // 100d xor eax, eax
    0xc3, // 100f ret
];

/// The same with `pmovzxbd`.
const PACKED_ZERO_EXTEND: &[u8] = &[
    0x66, 0x0f, 0x38, 0x31, 0x07, // 1000 pmovzxbd xmm0, dword [rdi]
    0x66, 0x0f, 0xd6, 0x06, // 1005 movq qword [rsi], xmm0
    0x0f, 0x17, 0x46, 0x08, // 1009 movhps qword [rsi + 8], xmm0
    0x31, 0xc0, // 100d xor eax, eax
    0xc3, // 100f ret
];

/// `movd xmm0, edi; pmovsxbd xmm1, xmm0`, stored a quadword at a time.
const PACKED_SIGN_EXTEND_ARGUMENT: &[u8] = &[
    0x66, 0x0f, 0x6e, 0xc7, // 1000 movd xmm0, edi
    0x66, 0x0f, 0x38, 0x21, 0xc8, // 1004 pmovsxbd xmm1, xmm0
    0x66, 0x0f, 0xd6, 0x0e, // 1009 movq qword [rsi], xmm1
    0x0f, 0x17, 0x4e, 0x08, // 100d movhps qword [rsi + 8], xmm1
    0xc3, // 1011 ret
];

/// `movd xmm0, edi; pmovsxwq xmm1, xmm0; pshufd xmm1, xmm1, 0x0e; movq rax, xmm1; ret`
///
/// The argument's high word, sign-extended to the upper quadword, and read
/// back out of it.
const PACKED_SIGN_EXTEND_HIGH_LANE: &[u8] = &[
    0x66, 0x0f, 0x6e, 0xc7, // 1000 movd xmm0, edi
    0x66, 0x0f, 0x38, 0x24, 0xc8, // 1004 pmovsxwq xmm1, xmm0
    0x66, 0x0f, 0x70, 0xc9, 0x0e, // 1009 pshufd xmm1, xmm1, 0x0e
    0x66, 0x48, 0x0f, 0x7e, 0xc8, // 100e movq rax, xmm1
    0xc3, // 1013 ret
];

/// A packed extension renders as the lanes the SDM defines: no opaque
/// operation is spelled and no part of the body is a marked gap.
fn assert_packed_extension_rendered(text: &str) {
    assert!(!text.contains("pmov"), "{text}");
    assert!(!text.contains("r2dec gap"), "{text}");
    assert!(text.contains(" 0 refused"), "{text}");
}

/// Sign and zero extension of each byte of a dword read from memory: all
/// sixteen bytes of the result are what the SDM says, and the bytes chosen
/// set the top bit, so the two extensions disagree.
#[test]
fn a_packed_extension_from_memory_renders_every_lane() {
    for (bytes, name, lanes) in [
        (
            PACKED_SIGN_EXTEND,
            "sign_extend_bytes",
            "0x00000001u, 0xffffff80u, 0x0000007fu, 0xfffffffeu",
        ),
        (
            PACKED_ZERO_EXTEND,
            "zero_extend_bytes",
            "0x00000001u, 0x00000080u, 0x0000007fu, 0x000000feu",
        ),
    ] {
        let text = rendered(bytes, name);
        assert_packed_extension_rendered(&text);
        run_rendered(
            name,
            &text,
            &format!(
                r#"int main(void) {{
    const uint8_t source[4] = {{0x01, 0x80, 0x7f, 0xfe}};
    const uint32_t want[4] = {{{lanes}}};
    uint32_t got[4];
    memset(got, 0xa5, sizeof got);
    if ({name}((uint64_t)(uintptr_t)source, (uint64_t)(uintptr_t)got) != 0) {{
        return 2;
    }}
    return memcmp(got, want, sizeof want) != 0;
}}"#
            ),
        );
    }
}

/// A packed extension of an argument reads the argument: the formals are the
/// thirty-two bits `movd` takes and the destination, not a local nothing
/// assigns, and the upper lane holds the sign of the argument's high word
/// rather than zero.
#[test]
fn a_packed_extension_of_an_argument_takes_the_argument() {
    let text = rendered(PACKED_SIGN_EXTEND_ARGUMENT, "sign_extend_argument");
    assert_packed_extension_rendered(&text);
    assert!(
        text.starts_with("void sign_extend_argument(uint32_t "),
        "{text}"
    );
    run_rendered(
        "sign_extend_argument",
        &text,
        r#"int main(void) {
    const uint32_t want[4] = {0x00000001u, 0xffffff80u, 0x0000007fu, 0xfffffffeu};
    uint32_t got[4];
    memset(got, 0xa5, sizeof got);
    sign_extend_argument(0xfe7f8001u, (uint64_t)(uintptr_t)got);
    return memcmp(got, want, sizeof want) != 0;
}"#,
    );

    let text = rendered(PACKED_SIGN_EXTEND_HIGH_LANE, "sign_extend_high_lane");
    assert_packed_extension_rendered(&text);
    assert!(
        text.starts_with("uint64_t sign_extend_high_lane(uint32_t "),
        "{text}"
    );
    run_rendered(
        "sign_extend_high_lane",
        &text,
        r#"int main(void) {
    if (sign_extend_high_lane(0x80000000u) != 0xffffffffffff8000ULL) {
        return 1;
    }
    if (sign_extend_high_lane(0x7fff1234u) != 0x7fffULL) {
        return 2;
    }
    if (sign_extend_high_lane(0xfffe0000u) != 0xfffffffffffffffeULL) {
        return 3;
    }
    return 0;
}"#,
    );
}

/// `vpmovzxbd ymm0, [rdi]`: eight bytes zero-extended to a 256-bit result,
/// whose halves are stored a quadword at a time.
///
/// ```text
///   1000  vpmovzxbd    ymm0, qword [rdi]
///   1005  vextracti128 xmm1, ymm0, 1
///   100b  vzeroupper
///   100e  movq         qword [rsi], xmm0
///   1012  movhps       qword [rsi + 8], xmm0
///   1016  movq         qword [rsi + 0x10], xmm1
///   101b  movhps       qword [rsi + 0x18], xmm1
///   101f  xor          eax, eax
///   1021  ret
/// ```
const WIDE_ZERO_EXTEND: &[u8] = &[
    0xc4, 0xe2, 0x7d, 0x31, 0x07, // 1000 vpmovzxbd ymm0, qword [rdi]
    0xc4, 0xe3, 0x7d, 0x39, 0xc1, 0x01, // 1005 vextracti128 xmm1, ymm0, 1
    0xc5, 0xf8, 0x77, // 100b vzeroupper
    0x66, 0x0f, 0xd6, 0x06, // 100e movq qword [rsi], xmm0
    0x0f, 0x17, 0x46, 0x08, // 1012 movhps qword [rsi + 8], xmm0
    0x66, 0x0f, 0xd6, 0x4e, 0x10, // 1016 movq qword [rsi + 0x10], xmm1
    0x0f, 0x17, 0x4e, 0x18, // 101b movhps qword [rsi + 0x18], xmm1
    0x31, 0xc0, // 101f xor eax, eax
    0xc3, // 1021 ret
];

/// The same with `vpmovsxbd`.
const WIDE_SIGN_EXTEND: &[u8] = &[
    0xc4, 0xe2, 0x7d, 0x21, 0x07, // 1000 vpmovsxbd ymm0, qword [rdi]
    0xc4, 0xe3, 0x7d, 0x39, 0xc1, 0x01, // 1005 vextracti128 xmm1, ymm0, 1
    0xc5, 0xf8, 0x77, // 100b vzeroupper
    0x66, 0x0f, 0xd6, 0x06, // 100e movq qword [rsi], xmm0
    0x0f, 0x17, 0x46, 0x08, // 1012 movhps qword [rsi + 8], xmm0
    0x66, 0x0f, 0xd6, 0x4e, 0x10, // 1016 movq qword [rsi + 0x10], xmm1
    0x0f, 0x17, 0x4e, 0x18, // 101b movhps qword [rsi + 0x18], xmm1
    0x31, 0xc0, // 101f xor eax, eax
    0xc3, // 1021 ret
];

/// A 256-bit result is a wide carrier the rendering defines, composed and
/// taken apart only by the helpers it also defines: the rendering compiles
/// with nothing but `<stdint.h>` above it, and computes every lane.
#[test]
fn a_256_bit_packed_extension_compiles_on_its_own() {
    for (bytes, name, widen) in [
        (WIDE_ZERO_EXTEND, "zero_extend_wide", "(uint32_t)source[i]"),
        (
            WIDE_SIGN_EXTEND,
            "sign_extend_wide",
            "(uint32_t)(int32_t)(int8_t)source[i]",
        ),
    ] {
        let text = rendered(bytes, name);
        assert_packed_extension_rendered(&text);
        assert!(
            text.starts_with("struct r2sleigh_bits_256 {\n    uint8_t bytes[32];\n};\n"),
            "{text}"
        );
        assert!(
            text.contains("r2sleigh_bits_insert_256_128(r2sleigh_bits_zero_extend_128_256("),
            "{text}"
        );
        run_rendered(
            name,
            &text,
            &format!(
                r#"int main(void) {{
    const uint8_t source[8] = {{0x01, 0x80, 0x7f, 0xfe, 0x00, 0xff, 0x81, 0x7e}};
    uint32_t want[8];
    uint32_t got[8];
    for (int i = 0; i < 8; i++) {{
        want[i] = {widen};
    }}
    memset(got, 0xa5, sizeof got);
    if ({name}((uint64_t)(uintptr_t)source, (uint64_t)(uintptr_t)got) != 0) {{
        return 2;
    }}
    return memcmp(got, want, sizeof want) != 0;
}}"#
            ),
        );
    }
}

/// `movdqu xmm0, [rdi]; movdqu [rsi], xmm0; xor eax, eax; ret`
const COPY_16: &[u8] = &[
    0xf3, 0x0f, 0x6f, 0x07, // 1000 movdqu xmm0, xmmword [rdi]
    0xf3, 0x0f, 0x7f, 0x06, // 1004 movdqu xmmword [rsi], xmm0
    0x31, 0xc0, // 1008 xor eax, eax
    0xc3, // 100a ret
];

/// `movdqu xmm2, [rdi]; movq [rsi], xmm2; movhps [rsi + 8], xmm2; xor eax, eax; ret`
const COPY_16_IN_HALVES: &[u8] = &[
    0xf3, 0x0f, 0x6f, 0x17, // 1000 movdqu xmm2, xmmword [rdi]
    0x66, 0x0f, 0xd6, 0x16, // 1004 movq qword [rsi], xmm2
    0x0f, 0x17, 0x56, 0x08, // 1008 movhps qword [rsi + 8], xmm2
    0x31, 0xc0, // 100c xor eax, eax
    0xc3, // 100e ret
];

/// `pmovsxbd xmm0, dword [rdi]; movdqu [rsi], xmm0; xor eax, eax; ret`
const SIGN_EXTEND_STORED_WHOLE: &[u8] = &[
    0x66, 0x0f, 0x38, 0x21, 0x07, // 1000 pmovsxbd xmm0, dword [rdi]
    0xf3, 0x0f, 0x7f, 0x06, // 1005 movdqu xmmword [rsi], xmm0
    0x31, 0xc0, // 1009 xor eax, eax
    0xc3, // 100b ret
];

/// `vmovdqu ymm0, [rdi]; vmovdqu [rsi], ymm0; xor eax, eax; vzeroupper; ret`
const COPY_32: &[u8] = &[
    0xc5, 0xfe, 0x6f, 0x07, // 1000 vmovdqu ymm0, ymmword [rdi]
    0xc5, 0xfe, 0x7f, 0x06, // 1004 vmovdqu ymmword [rsi], ymm0
    0x31, 0xc0, // 1008 xor eax, eax
    0xc5, 0xf8, 0x77, // 100a vzeroupper
    0xc3, // 100d ret
];

/// A load or store wider than eight bytes is typed as the storage it is --
/// a 128-bit integer, or the carrier a wider value is -- so the rendering is
/// C: it compiles, every byte it moves arrives, and none past them.
///
/// Such an access was typed `byte[N]` upstream, and `byte[16]` is not a C
/// type, so `*(byte[16]*)p` did not compile.
#[test]
fn an_access_wider_than_eight_bytes_moves_every_byte() {
    for (bytes, name, width) in [
        (COPY_16, "copy_16", 16),
        (COPY_16_IN_HALVES, "copy_16_in_halves", 16),
        (COPY_32, "copy_32", 32),
    ] {
        let text = rendered(bytes, name);
        assert!(!text.contains("byte["), "{text}");
        run_rendered(
            name,
            &text,
            &format!(
                r#"int main(void) {{
    _Alignas(32) uint8_t source[48];
    _Alignas(32) uint8_t got[48];
    for (int i = 0; i < 48; i++) {{
        source[i] = (uint8_t)(0x80 + 7 * i);
    }}
    memset(got, 0xa5, sizeof got);
    if ({name}((uint64_t)(uintptr_t)source, (uint64_t)(uintptr_t)got) != 0) {{
        return 2;
    }}
    if (memcmp(got, source, {width}) != 0) {{
        return 3;
    }}
    for (int i = {width}; i < 48; i++) {{
        if (got[i] != 0xa5) {{
            return 4;
        }}
    }}
    return 0;
}}"#
            ),
        );
    }

    let text = rendered(SIGN_EXTEND_STORED_WHOLE, "sign_extend_stored_whole");
    assert_packed_extension_rendered(&text);
    assert!(!text.contains("byte["), "{text}");
    run_rendered(
        "sign_extend_stored_whole",
        &text,
        r#"int main(void) {
    const uint8_t source[4] = {0x01, 0x80, 0x7f, 0xfe};
    const uint32_t want[4] = {0x00000001u, 0xffffff80u, 0x0000007fu, 0xfffffffeu};
    _Alignas(16) uint32_t got[8];
    memset(got, 0xa5, sizeof got);
    if (sign_extend_stored_whole((uint64_t)(uintptr_t)source, (uint64_t)(uintptr_t)got) != 0) {
        return 2;
    }
    if (memcmp(got, want, sizeof want) != 0) {
        return 3;
    }
    return got[4] != 0xa5a5a5a5u;
}"#,
    );
}

/// `movq xmm0, rdi; movq xmm1, rsi; pshufb xmm0, xmm1; movq rax, xmm0; ret`
///
/// `pshufb` is an operation the specification declares and gives no p-code,
/// and the lift does not model it.
const UNMODELLED_SHUFFLE: &[u8] = &[
    0x66, 0x48, 0x0f, 0x6e, 0xc7, // 1000 movq xmm0, rdi
    0x66, 0x48, 0x0f, 0x6e, 0xce, // 1005 movq xmm1, rsi
    0x66, 0x0f, 0x38, 0x00, 0xc1, // 100a pshufb xmm0, xmm1
    0x66, 0x48, 0x0f, 0x7e, 0xc0, // 100f movq rax, xmm0
    0xc3, // 1014 ret
];

/// A value no model gives a meaning is refused, and the refusal names the
/// specification's operation and where it stands, rather than the renderer
/// predicate that noticed it.
///
/// Both are the machine projection's: r2ssa decides the operation has no
/// projection and says which it is, and the renderer reads that. The site is
/// the operation's place in the SSA form `pdim` prints -- the third operation
/// of the block at 0x1000, after the two `movq` zero extensions.
#[test]
fn an_unmodelled_user_operation_is_refused_by_name() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: UNMODELLED_SHUFFLE.to_vec(),
        name: "shuffle",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let text = response.output.text().to_string();
    assert!(
        matches!(
            response.render_refusal,
            Some(r2dec::DecompileRenderRefusal::UnmodelledUserOperation {
                block: BASE,
                op: 2,
                ..
            })
        ),
        "{:?}\n{text}",
        response.render_refusal
    );
    assert!(
        text.starts_with(
            "/* r2sleigh refused shuffle: native rendering refused: unmodelled machine operation pshufb at 0x1000:2 */"
        ),
        "{text}"
    );
}

/// `vpxor` of two 256-bit loads, whose high half is read back:
///
/// ```text
///   1000  vmovdqu      ymm0, ymmword [rdi]
///   1004  vmovdqu      ymm1, ymmword [rsi]
///   1008  vpxor        ymm0, ymm0, ymm1
///   100c  vextracti128 xmm1, ymm0, 1
///   1012  vzeroupper
///   1015  movq         rax, xmm1
///   101a  ret
/// ```
///
/// The exclusive or is a 256-bit `INT_XOR`, an operator on a value no C
/// integer holds.
const WIDE_EXCLUSIVE_OR: &[u8] = &[
    0xc5, 0xfe, 0x6f, 0x07, // 1000 vmovdqu ymm0, ymmword [rdi]
    0xc5, 0xfe, 0x6f, 0x0e, // 1004 vmovdqu ymm1, ymmword [rsi]
    0xc5, 0xfd, 0xef, 0xc1, // 1008 vpxor ymm0, ymm0, ymm1
    0xc4, 0xe3, 0x7d, 0x39, 0xc1, 0x01, // 100c vextracti128 xmm1, ymm0, 1
    0xc5, 0xf8, 0x77, // 1012 vzeroupper
    0x66, 0x48, 0x0f, 0x7e, 0xc8, // 1015 movq rax, xmm1
    0xc3, // 101a ret
];

/// An operator on a carrier wider than any C integer has no C spelling: the
/// carrier is a struct, and a struct has no `^`. The function is refused as
/// such, rather than rendered as `struct r2sleigh_bits_256 x = a ^ b;`, which
/// no C compiler accepts.
#[test]
fn an_operator_on_a_wide_carrier_is_refused() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: WIDE_EXCLUSIVE_OR.to_vec(),
        name: "wide_xor",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let text = response.output.text().to_string();
    assert_eq!(
        response.render_refusal,
        Some(r2dec::DecompileRenderRefusal::UnrepresentableOperation),
        "{text}"
    );
    assert!(
        text.starts_with(
            "/* r2sleigh refused wide_xor: native rendering refused: unrepresentable operation"
        ),
        "{text}"
    );
    for operator in [" ^ ", " | ", " << ", " >> ", " & "] {
        assert!(!text.contains(operator), "{operator:?} in {text}");
    }
}

/// Two values held across a call to an import nothing declares, then stored:
///
/// ```text
///   1000  movsd xmm8, [rip + 0x27]    ; 0x1030
///   1009  mov   rsi, [rip + 0x28]     ; 0x1038
///   1010  call  0x1026                ; the import's stub
///   1015  movsd [rip + 0x22], xmm8    ; 0x1040
///   101e  mov   [rip + 0x23], rsi     ; 0x1048
///   1025  ret
///   1026  jmp   [rip + 0x24]          ; the stub, through its slot at 0x1050
/// ```
const HELD_ACROSS_A_CALL: &[u8] = &[
    0xf2, 0x44, 0x0f, 0x10, 0x05, 0x27, 0x00, 0x00, 0x00, // 1000 movsd xmm8, [rip + 0x27]
    0x48, 0x8b, 0x35, 0x28, 0x00, 0x00, 0x00, // 1009 mov rsi, [rip + 0x28]
    0xe8, 0x11, 0x00, 0x00, 0x00, // 1010 call 0x1026
    0xf2, 0x44, 0x0f, 0x11, 0x05, 0x22, 0x00, 0x00, 0x00, // 1015 movsd [rip + 0x22], xmm8
    0x48, 0x89, 0x35, 0x23, 0x00, 0x00, 0x00, // 101e mov [rip + 0x23], rsi
    0xc3, // 1025 ret
    0xff, 0x25, 0x24, 0x00, 0x00, 0x00, // 1026 jmp [rip + 0x24]
    0xcc, 0xcc, 0xcc, 0xcc, // 102c padding
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x3f, // 1030 1.5
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // 1038 a word
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1040 where xmm8 goes
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1048 where rsi goes
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1050 the stub's slot
];

/// Bytes at `BASE` that call an import whose stub is at `stub`.
struct ImportCaller {
    bytes: &'static [u8],
    stub: u64,
}

impl r2ssa::body::Program for ImportCaller {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let slice = self.bytes.get(offset..)?;
        (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
    }

    fn region(&self, vaddr: u64) -> Option<r2ssa::body::Region> {
        code_region(self.bytes.len(), vaddr)
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        vaddr == BASE || vaddr == self.stub
    }
}

impl Program for ImportCaller {
    fn holds_static_data(&self, _vaddr: u64) -> bool {
        false
    }

    /// Nothing here is loaded, so nothing is written by a loader.
    fn loader_writes(&self, _range: &std::ops::Range<u64>) -> bool {
        false
    }

    fn extents(&self) -> &r2types::ProgramExtents {
        const NONE: &r2types::ProgramExtents = &r2types::ProgramExtents::none();
        NONE
    }

    fn name_at(&self, vaddr: u64) -> Option<String> {
        self.import_at(vaddr)
            .or_else(|| (vaddr == BASE).then(|| "caller".to_owned()))
    }

    /// No prototype table declares this name, so nothing says what it touches.
    fn import_at(&self, vaddr: u64) -> Option<String> {
        (vaddr == self.stub).then(|| "undeclared_import".to_owned())
    }
}

/// The operation defining what one instruction stores, through the copies and lane reads between.
fn stored_value_origin(artifact: &r2ssa::SsaArtifact, instruction: u64) -> SSAOp {
    let graph = artifact.graph();
    let mut value = graph
        .insts_for_instruction(instruction)
        .iter()
        .find_map(|inst| match &graph.inst(*inst)?.payload {
            InstPayload::Op(SSAOp::Store { val, .. }) => graph.value_id_for_var(val),
            _ => None,
        })
        .expect("the instruction stores");
    loop {
        let inst = graph
            .def_inst(value)
            .and_then(|inst| graph.inst(inst))
            .expect("the stored value has a definition");
        match &inst.payload {
            InstPayload::Op(SSAOp::Copy { src, .. } | SSAOp::Subpiece { src, .. }) => {
                value = graph.value_id_for_var(src).expect("the copied value");
            }
            InstPayload::Op(op) => return op.clone(),
            InstPayload::Phi { .. } => panic!("a straight line has no merge"),
        }
    }
}

/// A call clobbers what its convention does not preserve: `xmm8` and `rsi` under System V, neither under Microsoft x64.
#[test]
fn what_a_call_clobbers_is_what_its_convention_says() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let program = ImportCaller {
        bytes: HELD_ACROSS_A_CALL,
        stub: 0x1026,
    };
    for (convention, clobbered) in [("amd64", true), ("ms", false)] {
        let prepared = r2engine::native::prepared(&machine.under(convention), &program, BASE)
            .expect("prepared");
        for store in [0x1015, 0x101e] {
            let origin = stored_value_origin(prepared.artifact(), store);
            assert_eq!(
                matches!(origin, SSAOp::CallDefine { .. }),
                clobbered,
                "{convention}: the store at {store:#x} reads what {origin:?} defined"
            );
        }
    }
}

/// Two AArch64 values held across a call to an import nothing declares, then stored:
///
/// ```text
///   1000  ldr  d8, 0x1030       ; callee-saved: its low 64 bits survive
///   1004  ldr  d16, 0x1038      ; caller-saved
///   1008  bl   0x1020           ; the import's stub
///   100c  adr  x9, 0x1040
///   1010  str  d8, [x9]
///   1014  str  d16, [x9, 8]
///   1018  ret
///   1020  ldr  x16, 0x1050 ; br x16   ; the stub, through its slot
/// ```
const AARCH64_HELD_ACROSS_A_CALL: &[u8] = &[
    0x88, 0x01, 0x00, 0x5c, // 1000 ldr d8, 0x1030
    0xb0, 0x01, 0x00, 0x5c, // 1004 ldr d16, 0x1038
    0x06, 0x00, 0x00, 0x94, // 1008 bl 0x1020
    0xa9, 0x01, 0x00, 0x10, // 100c adr x9, 0x1040
    0x28, 0x01, 0x00, 0xfd, // 1010 str d8, [x9]
    0x30, 0x05, 0x00, 0xfd, // 1014 str d16, [x9, 8]
    0xc0, 0x03, 0x5f, 0xd6, // 1018 ret
    0x1f, 0x20, 0x03, 0xd5, // 101c nop
    0x90, 0x01, 0x00, 0x58, // 1020 ldr x16, 0x1050
    0x00, 0x02, 0x1f, 0xd6, // 1024 br x16
    0x1f, 0x20, 0x03, 0xd5, // 1028 nop
    0x1f, 0x20, 0x03, 0xd5, // 102c nop
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x3f, // 1030 1.5
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x40, // 1038 2.5
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1040 where d8 goes
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1048 where d16 goes
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1050 the stub's slot
];

/// AAPCS64 keeps `d8` across a call and not `d16`.
#[test]
fn a_call_keeps_the_low_half_of_a_callee_saved_vector_register() {
    let machine = Machine::new("aarch64", "aarch64", 64);
    let program = ImportCaller {
        bytes: AARCH64_HELD_ACROSS_A_CALL,
        stub: 0x1020,
    };
    let prepared = r2engine::native::prepared(&machine.target(), &program, BASE).expect("prepared");
    for (store, clobbered) in [(0x1010, false), (0x1014, true)] {
        let origin = stored_value_origin(prepared.artifact(), store);
        assert_eq!(
            matches!(origin, SSAOp::CallDefine { .. }),
            clobbered,
            "the store at {store:#x} reads what {origin:?} defined"
        );
    }
}

/// An AArch64 argument held across a call to an import nothing declares, of
/// which only the low byte is read afterwards:
///
/// ```text
///   1000  stp  x29, x30, [sp, #-32]!
///   1004  str  x21, [sp, #16]
///   1008  mov  x21, x2           ; the whole register, held across the call
///   100c  add  x0, x0, x1
///   1010  mov  w1, #2
///   1014  bl   0x1028            ; the import's stub
///   1018  and  w0, w21, #0xff    ; the only byte of it anything reads
///   101c  ldr  x21, [sp, #16]
///   1020  ldp  x29, x30, [sp], #32
///   1024  ret
///   1028  ldr  x16, 0x1030 ; br x16   ; the stub, through its slot
/// ```
const AARCH64_NARROWED_ARGUMENT_BESIDE_A_CALL: &[u8] = &[
    0xfd, 0x7b, 0xbe, 0xa9, // 1000 stp x29, x30, [sp, #-32]!
    0xf5, 0x0b, 0x00, 0xf9, // 1004 str x21, [sp, #16]
    0xf5, 0x03, 0x02, 0xaa, // 1008 mov x21, x2
    0x00, 0x00, 0x01, 0x8b, // 100c add x0, x0, x1
    0x41, 0x00, 0x80, 0x52, // 1010 mov w1, #2
    0x05, 0x00, 0x00, 0x94, // 1014 bl 0x1028
    0xa0, 0x1e, 0x00, 0x12, // 1018 and w0, w21, #0xff
    0xf5, 0x0b, 0x40, 0xf9, // 101c ldr x21, [sp, #16]
    0xfd, 0x7b, 0xc2, 0xa8, // 1020 ldp x29, x30, [sp], #32
    0xc0, 0x03, 0x5f, 0xd6, // 1024 ret
    0x50, 0x00, 0x00, 0x58, // 1028 ldr x16, 0x1030
    0x00, 0x02, 0x1f, 0xd6, // 102c br x16
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1030 the stub's slot
];

/// A call nothing declares takes its arity from the argument registers the
/// body wrote before it. `x2` it never wrote: the interface declares only its
/// low byte, and the register is rebuilt from that lane for the whole read at
/// 0x1008, but the rebuild restates what the caller passed. The call takes
/// `x0` and `x1` and stops there.
#[test]
fn a_register_rebuilt_from_a_narrowed_formal_is_not_a_call_argument() {
    let machine = Machine::new("aarch64", "aarch64", 64);
    let program = ImportCaller {
        bytes: AARCH64_NARROWED_ARGUMENT_BESIDE_A_CALL,
        stub: 0x1028,
    };
    let prepared = r2engine::native::prepared(&machine.target(), &program, BASE).expect("prepared");
    let artifact: &r2ssa::SsaArtifact = prepared.artifact();
    let graph = artifact.graph();
    // The case this is about: the value of `x2` reaching the call has a
    // defining instruction, the rebuild, and none of the body's.
    let rebuilt = graph
        .values
        .iter()
        .filter(|value| {
            value.canonical_storage.is_some_and(|storage| {
                storage.space == r2ssa::CanonicalStorageSpace::Register && storage.size == 8
            }) && graph.def_inst(value.id).is_some()
                && !graph.written_by_body(value.id)
        })
        .map(|value| value.var.display_name())
        .collect::<Vec<_>>();
    assert_eq!(rebuilt.len(), 1, "one register rebuilt: {rebuilt:?}");
    let calls = &artifact.facts().boundaries.calls;
    assert_eq!(calls.len(), 1, "{calls:#?}");
    let call = calls.values().next().expect("the one call");
    let slots = call
        .arguments
        .iter()
        .map(|argument| match argument.slot {
            r2ssa::CallBoundarySlot::Register { index, .. } => index,
            ref other => panic!("an argument outside the registers: {other:?}"),
        })
        .collect::<Vec<_>>();
    assert_eq!(slots, [0, 1], "{call:#?}");

    let response = decompile(&machine.target(), &program, BASE).expect("decompile");
    let text = response.output.text();
    assert!(response.render_refusal.is_none(), "{text}");
    assert!(
        text.contains("undeclared_import(X0_0 + X1_0, 2);"),
        "{text}"
    );
}

/// Every register a shipped default convention names is one register of its machine, so none is dropped.
#[test]
fn every_register_a_default_convention_names_is_one_of_its_machine() {
    for (sleigh, family, bits) in [
        ("x86-64", "x86-64", 64),
        ("x86", "x86", 32),
        ("aarch64", "aarch64", 64),
        ("arm", "arm", 32),
    ] {
        let machine = Machine::new(sleigh, family, bits);
        let convention = machine
            .conventions
            .default_convention()
            .expect("a default convention");
        let unplaced = convention
            .clobbered
            .iter()
            .chain(&convention.preserved)
            .filter(|name| {
                let named = machine.embedded.arch.registers.iter();
                named
                    .filter(|register| register.name.eq_ignore_ascii_case(name))
                    .count()
                    != 1
            })
            .collect::<Vec<_>>();
        assert!(
            unplaced.is_empty(),
            "{sleigh}/{}: {unplaced:?}",
            convention.name
        );
        let effect = machine.effects[&convention.name]
            .as_ref()
            .expect("the default convention states a call effect");
        assert_eq!(
            effect.clobbered().len(),
            convention.clobbered.len(),
            "{sleigh}"
        );
        assert_eq!(
            effect.preserved().len(),
            convention.preserved.len(),
            "{sleigh}"
        );
    }
}

/// A block copy of `rdx` quadwords.
const REPEATED_MOVE: &[u8] = &[
    0x48, 0x89, 0xd1, // 0x1000 mov rcx, rdx
    0xf3, 0x48, 0xa5, // 0x1003 rep movsq
    0xc3, // 0x1006 ret
];

/// The specification's clear direction flag settles which way the copy walks.
#[test]
fn a_repeated_move_walks_the_way_the_specification_says() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: REPEATED_MOVE.to_vec(),
        name: "copy",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let text = response.output.text();
    assert!(response.render_refusal.is_none(), "{text}");
    assert!(text.contains("uint64_t* to = (uint64_t*)RDI_0;"), "{text}");
    assert!(
        text.contains("to[transferred] = ((uint64_t*)RSI_0)[transferred];"),
        "{text}"
    );
    assert!(text.contains("while (transferred != RDX_0)"), "{text}");
}

/// A block copy after a call to an import nothing declares, from callee-saved registers:
///
/// ```text
///   1000  call 0x1012             ; the import's stub
///   1005  mov  rdi, rbx
///   1008  mov  rsi, rbp
///   100b  mov  rcx, r12
///   100e  rep  movsq
///   1011  ret
///   1012  jmp  [rip + 8]          ; the stub, through its slot at 0x1020
/// ```
const MOVE_AFTER_A_CALL: &[u8] = &[
    0xe8, 0x0d, 0x00, 0x00, 0x00, // 1000 call 0x1012
    0x48, 0x89, 0xdf, // 1005 mov rdi, rbx
    0x48, 0x89, 0xee, // 1008 mov rsi, rbp
    0x4c, 0x89, 0xe1, // 100b mov rcx, r12
    0xf3, 0x48, 0xa5, // 100e rep movsq
    0xc3, // 1011 ret
    0xff, 0x25, 0x08, 0x00, 0x00, 0x00, // 1012 jmp [rip + 8]
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1018 padding
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1020 the stub's slot
];

/// The entry's clear direction flag survives a call because every x86 convention preserves it.
#[test]
fn a_clear_direction_flag_survives_a_call() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let program = ImportCaller {
        bytes: MOVE_AFTER_A_CALL,
        stub: 0x1012,
    };
    for convention in ["amd64", "ms"] {
        let response = decompile(&machine.under(convention), &program, BASE).expect("decompile");
        let text = response.output.text();
        assert!(response.render_refusal.is_none(), "{convention}\n{text}");
        // The import states no result, so the return is a residual. The
        // move's operands are registers the function entered holding, which C
        // cannot spell, so each read of one is a residual too: four in all.
        assert!(marks_an_unproven_return(text), "{convention}\n{text}");
        assert_eq!(
            text.matches("r2sleigh_residual_").count(),
            4,
            "{convention}\n{text}"
        );
        assert!(
            text.contains("; 3 held from entry, read as residuals (R12_0, RBP_0, RBX_0)"),
            "{convention}\n{text}"
        );
        // The copy still walks forward, which is what a clear flag means. The
        // residuals' site numbers are the emitter's text order, not pinned here.
        assert!(
            text.contains("to[transferred] = ((uint64_t*)r2sleigh_residual_u64("),
            "{convention}\n{text}"
        );
        assert!(text.contains("transferred++;"), "{convention}\n{text}");
        assert!(
            text.contains("while (transferred != r2sleigh_residual_u64("),
            "{convention}\n{text}"
        );
    }
}

/// How many instructions read the one value nothing can render.
const STORES_OF_AN_UNRENDERABLE_VALUE: u32 = 2_000;

/// `lzcnt ecx, edi`, then `mov [rsi + 4*i], ecx` for every `i`, then `xor eax, eax; ret`.
///
/// `lzcnt` is outside the machine vocabulary and has no C lowering, which is
/// the refusal this wants: its value is unproven, so is every store of it,
/// and the whole run is one marked gap. The readers fan out rather than
/// chain. A chain of single-reader values is an inline expression as tall as
/// the chain, a depth source of its own that is bounded where expressions are
/// built; this is about how many cells one occurrence answers for.
fn stores_of_an_unrenderable_value() -> Vec<u8> {
    let mut bytes = vec![0xf3, 0x0f, 0xbd, 0xcf];
    for store in 0..STORES_OF_AN_UNRENDERABLE_VALUE {
        bytes.extend_from_slice(&[0x89, 0x8e]);
        bytes.extend_from_slice(&(4 * store).to_le_bytes());
    }
    bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
    bytes
}

/// One gap answers for every cell its closure claims, on a small stack.
///
/// The gap here claims tens of thousands of cells. They used to hang off the
/// one gap statement one wrapper per cell, so every recursive pass over the
/// rendered tree recursed once per cell, and this aborted the process with a
/// stack overflow long before it finished; `fcn.1000414cc` in macOS `ssh`
/// did the same at the default eight megabytes. An occurrence now carries
/// its cells as one set, so the depth of the tree does not grow with them.
#[test]
fn one_gap_answers_for_thousands_of_cells_on_a_small_stack() {
    let rendering = std::thread::Builder::new()
        .name("half-megabyte stack".to_owned())
        .stack_size(512 << 10)
        .spawn(|| {
            let machine = Machine::new("x86-64", "x86-64", 64);
            let program = Fixture {
                bytes: stores_of_an_unrenderable_value(),
                name: "stores",
            };
            let response = decompile(&machine.target(), &program, BASE).expect("decompile");
            let observations = match response.binding_audit {
                r2engine::BindingShadowAuditOutcome::Complete { observations, .. } => observations,
                other => panic!("the gap accounts for every cell: {other:?}"),
            };
            (
                response.render_refusal.is_none(),
                response.output.text().to_string(),
                response.effect_obligations(),
                observations,
            )
        })
        .expect("spawn the rendering thread")
        .join()
        .expect("the rendering finishes on half a megabyte of stack");
    let (rendered, text, effects, observations) = rendering;
    assert!(rendered, "{text}");

    // One marker, and it covers every store.
    assert_eq!(text.matches("r2dec gap:").count(), 1, "{text}");
    let covered = text
        .split("covering ")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .and_then(|count| count.parse::<u32>().ok())
        .expect("the marker says how many operations it covers");
    assert!(covered > STORES_OF_AN_UNRENDERABLE_VALUE, "{text}");

    // Every store is a write the gap answers for, and no cell is left over.
    assert!(observations.equations_hold(), "{observations:?}");
    for domain in [observations.values, observations.uses, observations.writes] {
        assert_eq!(domain.unaccounted, 0, "{observations:?}");
        assert_eq!(domain.refused, 0, "{observations:?}");
    }
    assert!(
        observations.writes.gapped >= STORES_OF_AN_UNRENDERABLE_VALUE as usize,
        "{observations:?}"
    );

    // The proof line states what the ledger gapped, and that is every store.
    assert_eq!(effects.unaccounted, 0, "{effects:?}");
    assert!(
        effects.gapped >= STORES_OF_AN_UNRENDERABLE_VALUE as usize,
        "{effects:?}"
    );
    assert!(
        text.contains(&format!(", {} residual;", effects.gapped)),
        "{text}"
    );
}
