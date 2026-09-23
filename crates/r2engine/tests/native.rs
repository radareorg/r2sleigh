//! Decompiling from bytes and an address, with no radare2 in the process.

use std::collections::BTreeMap;

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

/// A jump table of absolute addresses, the form x86-64 uses:
///
/// ```text
///   1000  cmp  edi, 3              ; the bound the guard proves
///   1003  ja   0x1020              ; out of range takes the default
///   1005  mov  edi, edi            ; the index, zero-extended
///   1007  jmp  [rdi*8 + 0x1030]    ; read one entry of the table
///   100e  mov  eax, 10  ; ret      ; case 0
///   1014  mov  eax, 20  ; ret      ; case 1
///   101a  mov  eax, 30  ; ret      ; case 2
///   1020  mov  eax, -1  ; ret      ; default
///   1026  mov  eax, 40  ; ret      ; case 3
///   1030  the four entries
/// ```
const TABLE_SWITCH: &[u8] = &[
    0x83, 0xff, 0x03, // 1000 cmp edi, 3
    0x77, 0x1b, // 1003 ja 0x1020
    0x89, 0xff, // 1005 mov edi, edi
    0xff, 0x24, 0xfd, 0x30, 0x10, 0x00, 0x00, // 1007 jmp [rdi*8 + 0x1030]
    0xb8, 0x0a, 0x00, 0x00, 0x00, 0xc3, // 100e case 0
    0xb8, 0x14, 0x00, 0x00, 0x00, 0xc3, // 1014 case 1
    0xb8, 0x1e, 0x00, 0x00, 0x00, 0xc3, // 101a case 2
    0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3, // 1020 default
    0xb8, 0x28, 0x00, 0x00, 0x00, 0xc3, // 1026 case 3
    0x00, 0x00, 0x00, 0x00, // 102c padding
    0x0e, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1030 -> 0x100e
    0x14, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1038 -> 0x1014
    0x1a, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1040 -> 0x101a
    0x26, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1048 -> 0x1026
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
    fn holds_static_data(&self, _vaddr: u64) -> bool {
        // The fixture maps one run of instruction bytes and declares no
        // sections, so nothing in it is a place a string could live.
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
        bytes: ADD_TWO,
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
        bytes: CALLER,
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

#[test]
fn a_callee_that_returns_the_pushed_address_gives_its_caller_a_constant() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: PC_THUNK,
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
        bytes: PC_THUNK,
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

    fn is_entry(&self, vaddr: u64) -> bool {
        matches!(vaddr, BASE | 0x100a)
    }
}

impl Program for Importing {
    fn holds_static_data(&self, _vaddr: u64) -> bool {
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
        bytes: ARM_DEAD_LOAD,
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
        bytes: ARM_DEAD_LOAD,
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
        bytes: ARM_DEAD_LOAD,
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
        bytes: ARM_DEAD_LOAD,
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
        bytes: TABLE_SWITCH,
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
    assert!(!output.contains("gapped"), "{output}");
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
        bytes: BARRIER,
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
        bytes: ATOMIC_INCREMENT,
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
fn a_leaf_whose_barrier_is_only_a_user_operation_cannot_prove_its_frame() {
    // No prologue, no epilogue: this function never touches the stack pointer,
    // and it still cannot prove it. The barrier before the return is a
    // `CALLOTHER` -- an operation the specification could not express in p-code
    // -- so what it writes is not limited to the output it names, and the walk
    // that proves the stack pointer survived has to stop at it. `dmb` writes
    // nothing and `cpuid` writes four registers it never mentions; nothing
    // here tells them apart, and assuming the first cost this walk its
    // soundness.
    //
    // What recovers this function is modelling the barrier in the lift, so it
    // stops being a `CALLOTHER` at all. That is the same route the exclusive
    // pair below took, and it is blocked on stating the ordering the
    // specification gives rather than one chosen to make this pass.
    const BARRIER_LEAF: &[u8] = &[
        0x5f, 0xf0, 0x7f, 0xf5, // dmb sy
        0x1e, 0xff, 0x2f, 0xe1, // bx lr
    ];
    let machine = Machine::new("arm", "arm", 32);
    let target = machine.target();
    let program = Fixture {
        bytes: BARRIER_LEAF,
        name: "order",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    assert!(
        response.render_refusal.is_some(),
        "a user operation before the return proves nothing about the frame:\n{}",
        response.output
    );
}

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
        bytes: IRREDUCIBLE_COUNTER,
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

/// A repeated instruction that branches back to its own start is a loop the
/// machine graph and the walk both name, not a contradiction between them.
#[test]
fn a_repeated_scan_is_a_loop_on_its_own_instruction() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: REPEATED_SCAN,
        name: "scan",
    };
    let response = decompile(&target, &program, BASE).expect("the two graphs agree");
    let text = response.output.text();
    // Until the scan has a lowering, its zero-count guard is the named gap.
    assert!(
        response.render_refusal.is_none() || text.contains("0x1006"),
        "{:?}\n{}",
        response.render_refusal,
        response.output
    );
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

    fn is_entry(&self, vaddr: u64) -> bool {
        vaddr == BASE || vaddr == self.stub
    }
}

impl Program for ImportCaller {
    fn holds_static_data(&self, _vaddr: u64) -> bool {
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
        bytes: REPEATED_MOVE,
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
        assert!(!text.contains("r2dec gap"), "{convention}\n{text}");
        assert!(
            text.contains("to[transferred] = ((uint64_t*)RBP_0)[transferred];"),
            "{convention}\n{text}"
        );
        assert!(
            text.contains("while (transferred != R12_0)"),
            "{convention}\n{text}"
        );
    }
}
