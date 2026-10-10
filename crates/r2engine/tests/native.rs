//! Decompiling from bytes and an address, with no radare2 in the process.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::TABLE_SWITCH;

use r2abi::{CallingConvention, Platform, Prototypes, calling_convention};
use r2engine::native::{NativeTarget, Program, call_effect, decompile, staged};
use r2sleigh_lift::EmbeddedMachine;
use r2sleigh_lift::profile::{LanguageProfile, SpecStorage};
use r2source::{CanonicalStorageId, CanonicalStorageSpace, SourceCallEffect};
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
    /// The name of the convention the platform defaults to.
    default: &'static str,
    /// Each convention the machine is tried under, by radare2's name for it:
    /// the default, and Microsoft x64 under the Windows toolchain's
    /// specification where the language has one and it differs.
    conventions: BTreeMap<&'static str, Under>,
    prototypes: Prototypes,
    declarations: r2abi::Declarations,
}

/// One convention and what the engine reads beside it.
struct Under {
    convention: &'static CallingConvention,
    compiler: LanguageProfile,
    effect: Option<SourceCallEffect>,
}

impl Machine {
    fn new(sleigh: &str, family: &str, bits: u32) -> Self {
        Self::on(sleigh, family, bits, Platform::Unknown)
    }

    /// The machine as a platform's ABI describes it, beyond its conventions.
    fn on(sleigh: &str, family: &str, bits: u32, platform: Platform) -> Self {
        let embedded = r2sleigh_lift::embedded_machine(sleigh).expect("embedded machine");
        let under = |platform: Platform, specification: &str| {
            let compiler = LanguageProfile::parse(specification).expect("parses");
            let convention = calling_convention(family, bits, platform).expect("a convention");
            Under {
                convention,
                effect: call_effect(
                    &embedded.arch,
                    bits,
                    platform,
                    &compiler,
                    convention.variadic_count_register,
                ),
                compiler,
            }
        };
        let default = under(platform, embedded.compiler_spec);
        let name = default.convention.name;
        let mut conventions = BTreeMap::from([(name, default)]);
        if let Some(windows) = embedded.compiler_spec_of("windows") {
            let ms = under(Platform::Windows, windows);
            if ms.convention.name != name {
                conventions.insert(ms.convention.name, ms);
            }
        }
        Self {
            embedded,
            default: name,
            conventions,
            prototypes: Prototypes::embedded(),
            declarations: r2abi::Declarations::default(),
        }
    }

    /// The machine under its default convention.
    fn target(&self) -> NativeTarget<'_> {
        self.under(self.default)
    }

    /// The machine under one named convention.
    fn under(&self, name: &str) -> NativeTarget<'_> {
        let under = &self.conventions[name];
        NativeTarget {
            arch: &self.embedded.arch,
            disasm: &self.embedded.disasm,
            cpu: self.embedded.cpu,
            convention: under.convention,
            call_effect: under.effect.as_ref(),
            compiler: &under.compiler,
            dwarf: &self.embedded.dwarf,
            prototypes: &self.prototypes,
            declarations: &self.declarations,
        }
    }

    /// The compiler specification of the default convention.
    fn compiler(&self) -> &LanguageProfile {
        &self.conventions[self.default].compiler
    }
}

/// `len` bytes of code mapped at `BASE`, as one region an instruction can run in.
fn code_region(len: usize, vaddr: u64) -> Option<r2engine::body::Region> {
    let end = BASE + len as u64;
    (BASE..end)
        .contains(&vaddr)
        .then_some(r2engine::body::Region {
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

impl r2engine::body::Program for Fixture {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let slice = self.bytes.get(offset..)?;
        (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
    }

    fn region(&self, vaddr: u64) -> Option<r2engine::body::Region> {
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

/// A fixture whose program states that one function never returns.
struct Halting {
    fixture: Fixture,
    halts: u64,
}

impl r2engine::body::Program for Halting {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        self.fixture.read(vaddr, max)
    }

    fn region(&self, vaddr: u64) -> Option<r2engine::body::Region> {
        self.fixture.region(vaddr)
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        self.fixture.is_entry(vaddr)
    }

    fn returns(&self, callee: u64) -> bool {
        callee != self.halts
    }
}

impl Program for Halting {
    fn holds_static_data(&self, vaddr: u64) -> bool {
        self.fixture.holds_static_data(vaddr)
    }

    fn extents(&self) -> &r2types::ProgramExtents {
        self.fixture.extents()
    }

    fn name_at(&self, vaddr: u64) -> Option<String> {
        self.fixture.name_at(vaddr)
    }

    fn import_at(&self, vaddr: u64) -> Option<String> {
        self.fixture.import_at(vaddr)
    }
}

#[test]
fn a_function_is_decompiled_from_bytes_alone() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    assert_eq!(machine.compiler().stack_pointer.as_deref(), Some("RSP"));

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

impl r2engine::body::Program for PanickingCallee {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        assert!(vaddr < 0x100a, "a defect reading the callee at {vaddr:#x}");
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let slice = CALLER.get(offset..)?;
        (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
    }

    fn region(&self, vaddr: u64) -> Option<r2engine::body::Region> {
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

/// `push rbp; mov rbp, rsp; pop rbp; ret`, an empty `void` function with a frame pointer.
const EMPTY_FRAME: &[u8] = &[0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3];

/// `stp x29, x30, [sp, #-16]!; mov x29, sp; ldp x29, x30, [sp], #16; ret`: the same on AArch64.
const A64_EMPTY_FRAME: &[u8] = &[
    0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xfd, 0x7b, 0xc1, 0xa8, 0xc0, 0x03, 0x5f, 0xd6,
];

/// The body writes RBP only to restore the caller's, so it is no result: rendered as one, the
/// function returned the caller's frame pointer, which its source never does.
#[test]
fn a_frame_pointer_the_body_restores_is_no_result() {
    for text in rendered_both(EMPTY_FRAME, "empty_frame") {
        assert!(text.contains("void empty_frame(void)"), "{text}");
        assert!(!text.to_lowercase().contains("rbp_"), "{text}");
    }
    // AArch64's untouched x0 may be an argument handed back, so the result is unproven, not x29.
    let a64 = Machine::new("aarch64", "aarch64", 64);
    for text in rendered_both_on(&a64, A64_EMPTY_FRAME, "empty_frame") {
        assert!(text.contains("return r2sleigh_residual_u64("), "{text}");
        assert!(!text.to_lowercase().contains("x29_"), "{text}");
    }
}

/// A program where the called address is a library function by name, as an
/// import stub is: no body worth reading, and a declared prototype instead.
struct Importing;

impl r2engine::body::Program for Importing {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let slice = CALLER.get(offset..)?;
        (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
    }

    fn region(&self, vaddr: u64) -> Option<r2engine::body::Region> {
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

/// Staged declares the import as its prototype states and passes the argument at that type.
#[test]
fn a_staged_call_passes_a_declared_import_its_declared_types() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let response = staged(&target, &Importing, BASE).expect("decompile");
    let text = response.output.text();
    assert!(text.contains("strlen(const char*);"), "{text}");
    assert!(text.contains("strlen((const char*)"), "{text}");
}

#[test]
fn a_declared_prototype_gives_an_import_its_arguments() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let response = decompile(&target, &Importing, BASE).expect("decompile");

    // strlen takes one argument, the convention says it arrives in rdi, and
    // the declaration says what it is.
    assert!(
        response.output.text().contains("strlen(const char*)"),
        "{}",
        response.output
    );
    assert!(
        response
            .output
            .text()
            .contains("strlen((const char*)RDI_0)"),
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
    assert_eq!(machine.compiler().stack_pointer.as_deref(), Some("sp"));

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

/// A lane written into a vector register whose other bytes nobody reads.
///
/// `dup` fills all of v2, `mov v2.s[1], w1` inserts one lane into it, and the
/// `and` keeps the vector a 256-bit carrier; only the inserted lane reaches the
/// return, so `r2ssa::demand` releases the inserts'
/// bases to one shared zero constant wider than any C integer. The rendering
/// spells that zero where each insert reads it, and that is its occurrence:
/// spelling a fresh zero in its place instead left the constant read and
/// never rendered, and the seal refused the function as
/// `RenderedValueRequired`.
#[test]
fn a_released_wide_insert_base_is_rendered_where_it_is_read() {
    const LANE_INSERT: &[u8] = &[
        0x02, 0x0c, 0x04, 0x4e, // dup v2.4s, w0
        0x22, 0x1c, 0x0c, 0x4e, // mov v2.s[1], w1
        0x42, 0x1c, 0x23, 0x4e, // and v2.16b, v2.16b, v3.16b
        0x40, 0x3c, 0x0c, 0x0e, // umov w0, v2.s[1]
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ];
    let machine = Machine::new("aarch64", "aarch64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: LANE_INSERT.to_vec(),
        name: "lane",
    };
    // Both pipelines: the staged one writes the 256-bit Z registers through the same helpers.
    for pipeline in [decompile, staged] {
        let response = pipeline(&target, &program, BASE).expect("decompile");
        let output = response.output.text();
        assert!(
            response.render_refusal.is_none(),
            "{:?}\n{output}",
            response.render_refusal
        );
        assert!(output.contains("r2sleigh_bits_insert_"), "{output}");
        assert!(output.contains("return"), "{output}");
        assert!(!output.contains("ValueHasNoCType"), "{output}");
    }
}

/// ldr r0, [pc, 4]; mov r0, 0; bx lr; .word -- the load's value is overwritten.
const ARM_DEAD_LOAD: &[u8] = &[
    0x00, 0x00, 0x91, 0xe5, // 0x1000 ldr r0, [r1]: an address only the run knows
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

/// `TABLE_SWITCH` as gcc -O0 compiles it: the index is spilled to its home
/// on entry, the guard compares the home, and the dispatch reloads it.
///
/// ```text
///   1000  push rbp ; mov rbp, rsp
///   1004  mov  [rbp - 4], edi          ; the parameter's home
///   1007  cmp  dword [rbp - 4], 3      ; the guard reads the home
///   100b  ja   0x1033
///   100d  mov  eax, [rbp - 4]          ; and so does the dispatch
///   1010  jmp  [rax*8 + 0x1040]
///   1017  case 0 .. 102c case 3, 1033 default: mov eax, k ; pop rbp ; ret
///   1040  the four entries
/// ```
const SPILLED_TABLE_SWITCH: &[u8] = &[
    0x55, 0x48, 0x89, 0xe5, // 1000 push rbp; mov rbp, rsp
    0x89, 0x7d, 0xfc, // 1004 mov [rbp-4], edi
    0x83, 0x7d, 0xfc, 0x03, // 1007 cmp dword [rbp-4], 3
    0x77, 0x26, // 100b ja 0x1033
    0x8b, 0x45, 0xfc, // 100d mov eax, [rbp-4]
    0xff, 0x24, 0xc5, 0x40, 0x10, 0x00, 0x00, // 1010 jmp [rax*8 + 0x1040]
    0xb8, 0x0a, 0x00, 0x00, 0x00, 0x5d, 0xc3, // 1017 case 0
    0xb8, 0x14, 0x00, 0x00, 0x00, 0x5d, 0xc3, // 101e case 1
    0xb8, 0x1e, 0x00, 0x00, 0x00, 0x5d, 0xc3, // 1025 case 2
    0xb8, 0x28, 0x00, 0x00, 0x00, 0x5d, 0xc3, // 102c case 3
    0xb8, 0xff, 0xff, 0xff, 0xff, 0x5d, 0xc3, // 1033 default
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 103a padding
    0x17, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1040 -> 0x1017
    0x1e, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1048 -> 0x101e
    0x25, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1050 -> 0x1025
    0x2c, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1058 -> 0x102c
];

/// The guard bounds the home and the dispatch reads the home, so the bound
/// reaches the index only if the home is one value: the parameter's home is
/// promoted, while the saved frame pointer beside it stays a save.
#[test]
fn a_guard_on_a_parameters_home_bounds_the_dispatch_that_reloads_it() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: SPILLED_TABLE_SWITCH.to_vec(),
        name: "pick",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let output = response.output.text();
    assert!(output.contains("switch ("), "{output}");
    for (case, returns) in [(0, "10"), (1, "20"), (2, "30"), (3, "40")] {
        assert!(output.contains(&format!("case {case}:")), "{output}");
        assert!(output.contains(&format!("{returns};")), "{output}");
    }
    assert!(!output.contains("residual"), "{output}");
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

impl r2engine::body::Program for Unbounded {
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

    fn region(&self, vaddr: u64) -> Option<r2engine::body::Region> {
        let code = code_region(UNBOUNDED_TABLE.len(), vaddr);
        let end = TABLE + 16 + self.zero_filled;
        let table = (TABLE..end)
            .contains(&vaddr)
            .then_some(r2engine::body::Region {
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
        vec![(0x1020, r2engine::body::UnresolvedReason::IndirectBranch)]
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

/// A field of an element of a struct array, through a pointer the certified
/// accesses type by the width they read.
///
/// `v[i].beta = q; return v[i].beta + v[i].alpha;` over a 16-byte `Rec` is two
/// four-byte accesses at `v + 16 i + 4` and `v + 16 i`, so the parameter is
/// `uint32_t *`. Spelled `v[i].f_4` the rendering named a field of a scalar,
/// and spelled `v[i]` it would scale by four, not sixteen: the subscript
/// stands only where the declared element is the proven stride, and the C has
/// to compile and compute the original's answer.
#[test]
fn a_struct_stride_through_a_scalar_pointer_is_not_subscripted_by_the_scalar() {
    // clang -O0: every operand goes through its frame slot, and each access
    // recomputes `v + 16 i` from the reloaded parameter.
    const REC_INDEX: &[u8] = &[
        0x55, // push rbp
        0x48, 0x89, 0xe5, // mov rbp, rsp
        0x48, 0x89, 0x7d, 0xf8, // mov [rbp - 8], rdi
        0x89, 0x75, 0xf4, // mov [rbp - 12], esi
        0x89, 0x55, 0xf0, // mov [rbp - 16], edx
        0x8b, 0x4d, 0xf0, // mov ecx, [rbp - 16]
        0x48, 0x8b, 0x45, 0xf8, // mov rax, [rbp - 8]
        0x48, 0x63, 0x55, 0xf4, // movsxd rdx, [rbp - 12]
        0x48, 0xc1, 0xe2, 0x04, // shl rdx, 4
        0x48, 0x01, 0xd0, // add rax, rdx
        0x89, 0x48, 0x04, // mov [rax + 4], ecx
        0x48, 0x8b, 0x45, 0xf8, // mov rax, [rbp - 8]
        0x48, 0x63, 0x4d, 0xf4, // movsxd rcx, [rbp - 12]
        0x48, 0xc1, 0xe1, 0x04, // shl rcx, 4
        0x48, 0x01, 0xc8, // add rax, rcx
        0x8b, 0x40, 0x04, // mov eax, [rax + 4]
        0x48, 0x8b, 0x4d, 0xf8, // mov rcx, [rbp - 8]
        0x48, 0x63, 0x55, 0xf4, // movsxd rdx, [rbp - 12]
        0x48, 0xc1, 0xe2, 0x04, // shl rdx, 4
        0x48, 0x01, 0xd1, // add rcx, rdx
        0x03, 0x01, // add eax, [rcx]
        0x5d, // pop rbp
        0xc3, // ret
    ];
    let text = rendered(REC_INDEX, "rec_index");
    assert!(!text.contains(".f_"), "{text}");
    run_rendered(
        "rec_index",
        &text,
        r#"int main(void) {
    int32_t recs[4][4] = {{1, 2, 3, 4}, {5, 6, 7, 8}, {9, 10, 11, 12}, {13, 14, 15, 16}};
    if ((int32_t)rec_index((void*)recs, 2, 100) != 109) {
        return 2;
    }
    return recs[2][1] != 100;
}"#,
    );
}

/// A result register filled on one path and holding the caller's on the other.
///
/// The caller never fills `rax` on x86-64, so the arm that skips the `mov`
/// hands back no value the program produced. That is a return proven on some
/// paths only, which is unproven, not a `uint64_t` result: the merge of the
/// written `rax` with the entry one read the entry value on the skipped arm,
/// where nothing assigned it, and declaration placement refused the function.
#[test]
fn a_result_written_on_one_path_only_is_a_marked_gap() {
    const HALF_FILLED: &[u8] = &[
        0x83, 0xff, 0x09, // cmp edi, 9
        0x7e, 0x02, // jle ret
        0x89, 0xf8, // mov eax, edi
        0xc3, // ret
    ];
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: HALF_FILLED.to_vec(),
        name: "half",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let output = response.output.text();
    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{output}",
        response.render_refusal
    );
    assert!(marks_an_unproven_return(output), "{output}");
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

/// x86-64 with a header's prototype for the body at `BASE`, spelled `int`, `uint32_t`, `uint64_t`
/// or `void *`: a body writing both RAX and XMM0 does not say which one its caller reads.
fn declaring(name: &str, returns: &str, parameters: &[&str]) -> Machine {
    use r2abi::{Parameter, Prototype, Scalar, ScalarKind, Type, TypeGraph, Width};
    let mut graph = TypeGraph::new();
    let mut node = |spelled: &str| {
        let scalar = |kind, bits| {
            Type::Scalar(Scalar {
                kind,
                width: Width::Bits(bits),
                name: Some(spelled.to_owned()),
            })
        };
        match spelled {
            "int" => graph.add(scalar(ScalarKind::Signed, 32)),
            "uint32_t" => graph.add(scalar(ScalarKind::Unsigned, 32)),
            "uint64_t" => graph.add(scalar(ScalarKind::Unsigned, 64)),
            "void *" => {
                let target = graph.add(Type::Void);
                graph.add(Type::Pointer { target })
            }
            other => panic!("no type spelled {other}"),
        }
    };
    let parameters = parameters
        .iter()
        .map(|spelled| Parameter::new(node(spelled), *spelled, None::<String>))
        .collect();
    let return_type = node(returns);
    let mut declarations = r2abi::Declarations::new(graph);
    declarations.declare_function(
        BASE,
        Prototype {
            name: name.to_owned(),
            parameters,
            returns: returns.into(),
            return_type,
            ..Prototype::default()
        },
    );
    let mut machine = Machine::new("x86-64", "x86-64", 64);
    machine.declarations = declarations;
    machine
}

/// Render bytes of `machine` mapped at `BASE`, refusing nothing.
/// The function at `BASE` in both pipelines, legacy then staged, each rendered without a refusal.
fn rendered_both(bytes: &'static [u8], name: &'static str) -> [String; 2] {
    rendered_both_on(&Machine::new("x86-64", "x86-64", 64), bytes, name)
}

/// Legacy's definition and staged's translation unit, which defines the helpers it calls.
fn rendered_both_on(machine: &Machine, bytes: &'static [u8], name: &'static str) -> [String; 2] {
    let target = machine.target();
    let program = Fixture {
        bytes: bytes.to_vec(),
        name,
    };
    let legacy = decompile(&target, &program, BASE).expect("decompile");
    let staged = staged(&target, &program, BASE).expect("decompile");
    for response in [&legacy, &staged] {
        let text = response.output.text();
        assert!(response.render_refusal.is_none(), "{text}");
    }
    let unit = match &staged.output {
        r2engine::EngineRendering::Function(rendered) => rendered.emission().unit().to_string(),
        other => other.text().to_string(),
    };
    [legacy.output.text().to_string(), unit]
}

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

/// A prologue in a block the body branches back to: every pass opens another
/// frame under the last, so no displacement names one slot on both arrivals.
const PROLOGUE_IN_A_LOOP: &[u8] = &[
    0x48, 0x83, 0xec, 0x10, // 0x1000 sub rsp, 0x10
    0x48, 0x89, 0x3c, 0x24, // 0x1004 mov [rsp], rdi
    0x48, 0xff, 0xcf, // 0x1008 dec rdi
    0x75, 0xf3, // 0x100b jnz 0x1000
    0x48, 0x8b, 0x04, 0x24, // 0x100d mov rax, [rsp]
    0x48, 0x83, 0xc4, 0x10, // 0x1011 add rsp, 0x10
    0xc3, // 0x1015 ret
];

/// The same body with the branch taken past the prologue, which runs once.
const PROLOGUE_BEFORE_A_LOOP: &[u8] = &[
    0x48, 0x83, 0xec, 0x10, // 0x1000 sub rsp, 0x10
    0x48, 0x89, 0x3c, 0x24, // 0x1004 mov [rsp], rdi
    0x48, 0xff, 0xcf, // 0x1008 dec rdi
    0x75, 0xf7, // 0x100b jnz 0x1004
    0x48, 0x8b, 0x04, 0x24, // 0x100d mov rax, [rsp]
    0x48, 0x83, 0xc4, 0x10, // 0x1011 add rsp, 0x10
    0xc3, // 0x1015 ret
];

/// Promotion names a frame slot by its place under the frame the entry
/// block's prologue opens, which holds only if that block runs once, on the
/// way in: a slot is promoted past a prologue the body loops after, and kept
/// in memory where the body loops back through it.
#[test]
fn a_frame_slot_is_promoted_only_where_the_prologue_runs_once() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let promoted = |bytes: &[u8]| {
        let program = Fixture {
            bytes: bytes.to_vec(),
            name: "framed",
        };
        let prepared = r2engine::native::prepared(&target, &program, BASE).expect("prepared");
        prepared.artifact().function().promoted_slots().len()
    };
    assert!(promoted(PROLOGUE_BEFORE_A_LOOP) > 0);
    assert_eq!(promoted(PROLOGUE_IN_A_LOOP), 0);
}

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

/// `v ^= 0xff` on the low byte of a spilled `uint64_t`, as gcc -O0 writes
/// siphash's `xor dl, 0xff`.
const FLIP_LOW_BYTE: &[u8] = &[
    0x55, // 0x1000 push rbp
    0x48, 0x89, 0xe5, // 0x1001 mov rbp, rsp
    0x48, 0x89, 0x7d, 0xf8, // 0x1004 mov [rbp-8], rdi
    0x48, 0x8b, 0x45, 0xf8, // 0x1008 mov rax, [rbp-8]
    0x34, 0xff, // 0x100c xor al, 0xff
    0x48, 0x89, 0x45, 0xf8, // 0x100e mov [rbp-8], rax
    0x48, 0x8b, 0x45, 0xf8, // 0x1012 mov rax, [rbp-8]
    0x5d, // 0x1016 pop rbp
    0xc3, // 0x1017 ret
];

/// mov rax, rdi; mov edx, esi; mov ah, dl; ret -- the second byte replaced.
const REPLACE_SECOND_BYTE: &[u8] = &[
    0x48, 0x89, 0xf8, // 0x1000 mov rax, rdi
    0x89, 0xf2, // 0x1003 mov edx, esi
    0x88, 0xd4, // 0x1005 mov ah, dl
    0xc3, // 0x1007 ret
];

/// mov rax, rdi; mov ax, si; not rax; ret -- the low half-word replaced,
/// and then the whole register read.
const REPLACE_LOW_WORD: &[u8] = &[
    0x48, 0x89, 0xf8, // 0x1000 mov rax, rdi
    0x66, 0x89, 0xf0, // 0x1003 mov ax, si
    0x48, 0xf7, 0xd0, // 0x1006 not rax
    0xc3, // 0x1009 ret
];

/// A write to part of a register keeps the rest of the register.
///
/// The lane's mask was spelled `~(uint8_t)0`, which C promotes to the `int`
/// -1 before the complement applies; widened to the register it is all ones,
/// so `root & ~mask` kept nothing and every bit above the lane was lost. The
/// renderings are compiled and run, so C's own promotion rules judge them.
#[test]
fn a_write_to_part_of_a_register_keeps_the_rest_of_it() {
    let text = rendered(FLIP_LOW_BYTE, "flip_low_byte");
    run_rendered(
        "flip_low_byte",
        &text,
        r#"int main(void) {
    const uint64_t cases[] = {0x1122334455667788ULL, 0, 0xffffffffffffffffULL, 0xff00ULL};
    for (int i = 0; i < 4; i++) {
        if (flip_low_byte(cases[i]) != (cases[i] ^ 0xff)) {
            return 1 + i;
        }
    }
    return 0;
}"#,
    );

    let text = rendered(REPLACE_SECOND_BYTE, "replace_second_byte");
    run_rendered(
        "replace_second_byte",
        &text,
        r#"int main(void) {
    const uint64_t roots[] = {0x1122334455667788ULL, 0, 0xffffffffffffffffULL};
    const uint64_t lanes[] = {0xa5, 0x1ff, 0};
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            uint64_t want = (roots[i] & ~0xff00ULL) | (lanes[j] & 0xff) << 8;
            if (replace_second_byte(roots[i], lanes[j]) != want) {
                return 1 + 3 * i + j;
            }
        }
    }
    return 0;
}"#,
    );

    let text = rendered(REPLACE_LOW_WORD, "replace_low_word");
    run_rendered(
        "replace_low_word",
        &text,
        r#"int main(void) {
    const uint64_t roots[] = {0x1122334455667788ULL, 0, 0xffffffffffffffffULL};
    const uint64_t lanes[] = {0xa5a5, 0x1ffff, 0};
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            uint64_t want = ~((roots[i] & ~0xffffULL) | (lanes[j] & 0xffff));
            if (replace_low_word(roots[i], lanes[j]) != want) {
                return 1 + 3 * i + j;
            }
        }
    }
    return 0;
}"#,
    );
}

/// `int typed_compete(int q) { g_sink = q; g_note = q; return g_sink +
/// (int)g_note; }` for an `int g_sink` and a `long g_note` at fixed
/// addresses, as gcc -O0 writes it: the parameter spilled, and each store
/// made from its own reload, the second sign-extended.
#[cfg(target_os = "linux")]
const TYPED_COMPETE: &[u8] = &[
    0x55, // 0x1000 push rbp
    0x48, 0x89, 0xe5, // 0x1001 mov rbp, rsp
    0x89, 0x7d, 0xfc, // 0x1004 mov [rbp-4], edi
    0x8b, 0x45, 0xfc, // 0x1007 mov eax, [rbp-4]
    0x89, 0x04, 0x25, 0x08, 0x00, 0x00, 0x40, // 0x100a mov [0x40000008], eax
    0x8b, 0x45, 0xfc, // 0x1011 mov eax, [rbp-4]
    0x48, 0x98, // 0x1014 cdqe
    0x48, 0x89, 0x04, 0x25, 0x00, 0x00, 0x00, 0x40, // 0x1016 mov [0x40000000], rax
    0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x40, // 0x101e mov rax, [0x40000000]
    0x89, 0xc2, // 0x1026 mov edx, eax
    0x8b, 0x04, 0x25, 0x08, 0x00, 0x00, 0x40, // 0x1028 mov eax, [0x40000008]
    0x01, 0xd0, // 0x102f add eax, edx
    0x5d, // 0x1031 pop rbp
    0xc3, // 0x1032 ret
];

/// A store writes the bytes the instruction writes, whatever its value is typed.
///
/// The sign extension of the parameter's reload was certified as the reload
/// itself, so the eight-byte value carried the four-byte parameter's type,
/// and the store was spelled at that type: `*(uint32_t*)g_note = ...` left
/// the upper four bytes of `g_note` as they were. The harness maps both
/// globals, fills them, and checks every byte after each call. The globals
/// sit at a fixed address the harness maps with a Linux mapping.
#[cfg(target_os = "linux")]
#[test]
fn a_store_writes_the_bytes_the_instruction_writes() {
    let text = rendered(TYPED_COMPETE, "typed_compete");
    run_rendered(
        "typed_compete",
        &text,
        r#"#include <sys/mman.h>
/* -std=c11 hides the Linux names; the values are the kernel's. */
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
int main(void) {
    void *page = mmap((void *)0x40000000, 4096, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (page != (void *)0x40000000) {
        return 100;
    }
    volatile int64_t *g_note = (volatile int64_t *)0x40000000;
    volatile uint32_t *g_sink = (volatile uint32_t *)0x40000008;
    const int32_t cases[] = {-1, INT32_MIN, 7, 0};
    for (int i = 0; i < 4; i++) {
        *g_note = 0x5555555555555555LL;
        *g_sink = 0x55555555u;
        uint32_t sum = (uint32_t)typed_compete((uint32_t)cases[i]);
        if (*g_note != (int64_t)cases[i]) {
            return 1 + i;
        }
        if (*g_sink != (uint32_t)cases[i] || sum != 2u * (uint32_t)cases[i]) {
            return 11 + i;
        }
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
    let text = rendered_on(
        &declaring("high_qword", "uint64_t", &["uint64_t"]),
        HIGH_QWORD,
        "high_qword",
    );
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
        let text = rendered_on(&declaring(name, "int", &["void *", "void *"]), bytes, name);
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
    if ({name}((void*)source, (void*)got) != 0) {{
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
    sign_extend_argument(0xfe7f8001u, (void*)got);
    return memcmp(got, want, sizeof want) != 0;
}"#,
    );

    let text = rendered_on(
        &declaring("sign_extend_high_lane", "uint64_t", &["uint32_t"]),
        PACKED_SIGN_EXTEND_HIGH_LANE,
        "sign_extend_high_lane",
    );
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
        let text = rendered_on(&declaring(name, "int", &["void *", "void *"]), bytes, name);
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
    if ({name}((void*)source, (void*)got) != 0) {{
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
        let machine = declaring(name, "int", &["void *", "void *"]);
        // Staged has no 256-bit carrier yet (ROADMAP D, wide values), so it is graded to 16 bytes.
        let pipelines = if width > 16 { 1 } else { 2 };
        let rendered = rendered_both_on(&machine, bytes, name);
        for (pipeline, text) in ["legacy", "staged"].iter().zip(rendered).take(pipelines) {
            assert!(!text.contains("byte["), "{text}");
            run_rendered(
                &format!("{name}_{pipeline}"),
                &text,
                &format!(
                    r#"int main(void) {{
    _Alignas(32) uint8_t source[48];
    _Alignas(32) uint8_t got[48];
    for (int i = 0; i < 48; i++) {{
        source[i] = (uint8_t)(0x80 + 7 * i);
    }}
    memset(got, 0xa5, sizeof got);
    if ({name}((void*)source, (void*)got) != 0) {{
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
    }

    let text = rendered_on(
        &declaring("sign_extend_stored_whole", "int", &["void *", "void *"]),
        SIGN_EXTEND_STORED_WHOLE,
        "sign_extend_stored_whole",
    );
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
    if (sign_extend_stored_whole((void*)source, (void*)got) != 0) {
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
    let machine = declaring("shuffle", "uint64_t", &["uint64_t", "uint64_t"]);
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

/// The byte widening a vectorised count does between its compare and its
/// accumulate (`mem_scan2` at clang -O2), and a word reversal:
///
/// ```text
///   widen:   movd xmm0, edi; punpcklbw xmm0, xmm0; pshuflw xmm0, xmm0, 0x50
///            pshufd xmm0, xmm0, 0x50; movq rax, xmm0; ret
///   reverse: movq xmm0, rdi; pshuflw xmm0, xmm0, 0x1b; movq rax, xmm0; ret
/// ```
const WIDENED_BYTE: &[u8] = &[
    0x66, 0x0f, 0x6e, 0xc7, // movd xmm0, edi
    0x66, 0x0f, 0x60, 0xc0, // punpcklbw xmm0, xmm0
    0xf2, 0x0f, 0x70, 0xc0, 0x50, // pshuflw xmm0, xmm0, 0x50
    0x66, 0x0f, 0x70, 0xc0, 0x50, // pshufd xmm0, xmm0, 0x50
    0x66, 0x48, 0x0f, 0x7e, 0xc0, // movq rax, xmm0
    0xc3, // ret
];
const REVERSED_WORDS: &[u8] = &[
    0x66, 0x48, 0x0f, 0x6e, 0xc7, // movq xmm0, rdi
    0xf2, 0x0f, 0x70, 0xc0, 0x1b, // pshuflw xmm0, xmm0, 0x1b
    0x66, 0x48, 0x0f, 0x7e, 0xc0, // movq rax, xmm0
    0xc3, // ret
];

/// `pshuflw` is a user operation the specification declares without p-code,
/// and the lift gives it the SDM's meaning, so a function using it renders,
/// and the C computes what the machine does: the low byte repeated eight
/// times, and the four words in reverse order.
#[test]
fn a_word_shuffle_renders_what_the_machine_computes() {
    let declared = |name| declaring(name, "uint64_t", &["uint64_t"]);
    let widen = rendered_on(&declared("widen"), WIDENED_BYTE, "widen");
    let reverse = rendered_on(&declared("reverse"), REVERSED_WORDS, "reverse");
    run_rendered(
        "word_shuffle",
        &format!("{widen}\n{reverse}"),
        r#"int main(void) {
    const uint64_t cases[] = {0, 1, 0xff, 0x1234, 0x80c3, 0x0123456789abcdefull, ~0ull};
    for (int i = 0; i < 7; i++) {
        uint64_t x = cases[i];
        if (widen(x) != (x & 0xff) * 0x0101010101010101ull) {
            return 1 + i;
        }
        uint64_t reversed = (x >> 48) | ((x >> 16) & 0xffff0000ull)
            | ((x << 16) & 0xffff00000000ull) | (x << 48);
        if (reverse(x) != reversed) {
            return 10 + i;
        }
    }
    return 0;
}"#,
    );
}

/// `tzcnt rax, rdi; ret`, and `mov rax, rsi; bsf rax, rdi; ret`.
///
/// Both are p-code loops in the specification. TZCNT counts the width at
/// zero; BSF writes nothing the machine defines at zero, and the destination
/// keeps what the `mov` put there.
const TRAILING_ZEROS: &[u8] = &[
    0xf3, 0x48, 0x0f, 0xbc, 0xc7, // tzcnt rax, rdi
    0xc3, // ret
];
const LOWEST_SET_BIT: &[u8] = &[
    0x48, 0x89, 0xf0, // mov rax, rsi
    0x48, 0x0f, 0xbc, 0xc7, // bsf rax, rdi
    0xc3, // ret
];

/// A bit scan is lifted as the count it computes, not as a loop the renderer
/// cannot follow, so functions using `tzcnt` and `bsf` render, and compute
/// what the machine does at every source, zero included.
#[test]
fn a_bit_scan_renders_as_the_count_it_computes() {
    let trailing = rendered_both(TRAILING_ZEROS, "trailing");
    let lowest = rendered_both(LOWEST_SET_BIT, "lowest");
    for (pipeline, (trailing, lowest)) in ["legacy", "staged"]
        .iter()
        .zip(trailing.iter().zip(&lowest))
    {
        run_rendered(
            &format!("bit_scan_{pipeline}"),
            &format!("{trailing}\n{lowest}"),
            r#"int main(void) {
    const uint64_t cases[] = {0, 1, 2, 0x80, 0x100, 0x8000000000000000ull, 0x0123456789abcde0ull, ~0ull};
    for (int i = 0; i < 8; i++) {
        uint64_t x = cases[i];
        uint64_t count = x ? (uint64_t)__builtin_ctzll(x) : 64;
        if (trailing(x) != count) {
            return 1 + i;
        }
        if (lowest(x, 0x5a5a5a5a5a5a5a5aull) != (x ? count : 0x5a5a5a5a5a5a5a5aull)) {
            return 10 + i;
        }
    }
    return 0;
}"#,
        );
    }
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
    let machine = declaring("wide_xor", "uint64_t", &["void *", "void *"]);
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

impl r2engine::body::Program for ImportCaller {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let offset = usize::try_from(vaddr.checked_sub(BASE)?).ok()?;
        let slice = self.bytes.get(offset..)?;
        (!slice.is_empty()).then(|| slice[..slice.len().min(max)].to_vec())
    }

    fn region(&self, vaddr: u64) -> Option<r2engine::body::Region> {
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
fn stored_value_origin(artifact: &r2ssa::SsaArtifact, instruction: u64) -> SSAOp<r2ssa::ValueId> {
    let graph = artifact.graph();
    let mut value = graph
        .insts_for_instruction(instruction)
        .iter()
        .find_map(|inst| match &graph.inst(*inst)?.payload {
            InstPayload::Op(SSAOp::Store { val, .. }) => Some(*val),
            _ => None,
        })
        .expect("the instruction stores");
    let mut last = None;
    loop {
        // A value read from bytes the program never writes is the literal they hold: its copy, or the literal, is the origin.
        if graph.value(value).is_some_and(|value| value.var.is_const()) {
            return last.unwrap_or(SSAOp::Copy {
                dst: value,
                src: value,
            });
        }
        let inst = graph
            .def_inst(value)
            .and_then(|inst| graph.inst(inst))
            .expect("the stored value has a definition");
        match &inst.payload {
            InstPayload::Op(op @ (SSAOp::Copy { src, .. } | SSAOp::Subpiece { src, .. })) => {
                last = Some(op.clone());
                value = *src;
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
/// 0x1008, but the rebuild restates what the caller passed, so it is no write.
/// It is this function's own parameter, though, which the call may be handed
/// unchanged: the count stops at `x0`, `x1` unproven, and the call is a
/// residual rather than `undeclared_import(X0_0 + X1_0, 2)` (decided 2026-10-07).
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
    assert!(!call.arguments_complete, "{call:#?}");
    assert!(call.results_complete, "{call:#?}");

    let response = decompile(&machine.target(), &program, BASE).expect("decompile");
    let text = response.output.text();
    assert!(
        !text.contains("undeclared_import(X0_0 + X1_0, 2);"),
        "{text}"
    );
}

/// Every register a default prototype names is one register of its
/// machine, and the call effect states it: none is dropped on the way.
#[test]
fn every_register_a_default_prototype_names_is_one_of_its_machine() {
    for (sleigh, family, bits) in [
        ("x86-64", "x86-64", 64),
        ("x86", "x86", 32),
        ("aarch64", "aarch64", 64),
        ("arm", "arm", 32),
    ] {
        let machine = Machine::new(sleigh, family, bits);
        let prototype = machine
            .compiler()
            .default_prototype()
            .expect("a default prototype");
        let named = prototype
            .inputs
            .iter()
            .chain(&prototype.outputs)
            .map(|entry| &entry.storage)
            .chain(&prototype.killed_by_call)
            .chain(&prototype.unaffected)
            .filter_map(|storage| match storage {
                SpecStorage::Register(name) => Some(name.as_str()),
                SpecStorage::Address { .. } => None,
            })
            .collect::<Vec<_>>();
        assert!(!named.is_empty(), "{sleigh}");
        let effect = machine.conventions[machine.default]
            .effect
            .as_ref()
            .expect("the default prototype states a call effect");
        for register in named {
            let placed = machine
                .embedded
                .arch
                .registers
                .iter()
                .filter(|candidate| candidate.name.eq_ignore_ascii_case(register))
                .map(|candidate| CanonicalStorageId {
                    space: CanonicalStorageSpace::Register,
                    offset: candidate.offset,
                    size: candidate.size,
                })
                .collect::<Vec<_>>();
            assert_eq!(placed.len(), 1, "{sleigh}: {register}");
            assert!(
                effect.clobbered().contains(&placed[0]) || effect.preserved().contains(&placed[0]),
                "{sleigh}: {register} is in neither list"
            );
        }
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
            (
                response.render_refusal.is_none(),
                response.output.text().to_string(),
                response.effect_obligations(),
            )
        })
        .expect("spawn the rendering thread")
        .join()
        .expect("the rendering finishes on half a megabyte of stack");
    let (rendered, text, effects) = rendering;
    // Rendered, so the observation journal sealed with every value, use and
    // write accounted for and none refused: a seal short of that refuses.
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

/// gcc -O0 `long mul_div(long a, long b) { return b ? a * 7 / b + a % b : 0; }`,
/// both parameters spilled to their homes and read back for each division:
///
/// ```text
///   1000  endbr64
///   1004  push rbp ; mov rbp, rsp
///   1008  mov [rbp-8], rdi ; mov [rbp-0x10], rsi
///   1010  cmp qword [rbp-0x10], 0 ; jne 0x101e
///   1017  mov eax, 0 ; jmp 0x1045
///   101e  mov rdx, [rbp-8] ; mov rax, rdx ; shl rax, 3 ; sub rax, rdx
///   102c  cqo ; idiv qword [rbp-0x10] ; mov rcx, rax
///   1035  mov rax, [rbp-8] ; cqo ; idiv qword [rbp-0x10]
///   103f  mov rax, rdx ; add rax, rcx
///   1045  pop rbp ; ret
/// ```
const MUL_DIV_O0: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, // 1000 endbr64
    0x55, // 1004 push rbp
    0x48, 0x89, 0xe5, // 1005 mov rbp, rsp
    0x48, 0x89, 0x7d, 0xf8, // 1008 mov [rbp-8], rdi
    0x48, 0x89, 0x75, 0xf0, // 100c mov [rbp-0x10], rsi
    0x48, 0x83, 0x7d, 0xf0, 0x00, // 1010 cmp qword [rbp-0x10], 0
    0x75, 0x07, // 1015 jne 0x101e
    0xb8, 0x00, 0x00, 0x00, 0x00, // 1017 mov eax, 0
    0xeb, 0x27, // 101c jmp 0x1045
    0x48, 0x8b, 0x55, 0xf8, // 101e mov rdx, [rbp-8]
    0x48, 0x89, 0xd0, // 1022 mov rax, rdx
    0x48, 0xc1, 0xe0, 0x03, // 1025 shl rax, 3
    0x48, 0x29, 0xd0, // 1029 sub rax, rdx
    0x48, 0x99, // 102c cqo
    0x48, 0xf7, 0x7d, 0xf0, // 102e idiv qword [rbp-0x10]
    0x48, 0x89, 0xc1, // 1032 mov rcx, rax
    0x48, 0x8b, 0x45, 0xf8, // 1035 mov rax, [rbp-8]
    0x48, 0x99, // 1039 cqo
    0x48, 0xf7, 0x7d, 0xf0, // 103b idiv qword [rbp-0x10]
    0x48, 0x89, 0xd0, // 103f mov rax, rdx
    0x48, 0x01, 0xc8, // 1042 add rax, rcx
    0x5d, // 1045 pop rbp
    0xc3, // 1046 ret
];

/// `cqo` writes the sign word of a reload of `a` into RDX: the high half of
/// its sign extension, the same width as `a`'s home and computed from what
/// the home holds, but not what it holds. Certifying it as a reload of the
/// home made it a member of the parameter's binding, and the rendering then
/// assigned the sign word to `a` before the division read `a` again.
///
/// The value view says what a reload's copies are: only a value with the
/// reload's bits at its width is the slot's, so no lane at a non-zero offset
/// -- a sign word -- is ever certified as a home's contents, and the
/// rendering writes neither parameter.
#[test]
fn the_sign_word_a_division_extends_into_is_not_the_parameter_it_extends() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let program = Fixture {
        bytes: MUL_DIV_O0.to_vec(),
        name: "mul_div",
    };
    let prepared = r2engine::native::prepared(&machine.target(), &program, BASE).expect("prepared");
    let artifact: &r2ssa::SsaArtifact = prepared.artifact();
    let graph = artifact.graph();
    let is_high_lane = |value: r2ssa::ValueId| {
        graph
            .def_inst(value)
            .and_then(|inst| graph.inst(inst))
            .is_some_and(|inst| {
                matches!(
                    inst.payload,
                    InstPayload::Op(SSAOp::Subpiece { offset, .. }) if offset > 0
                )
            })
    };
    let high_lanes = graph
        .values
        .iter()
        .filter(|value| value.var.size == 8 && is_high_lane(value.id))
        .map(|value| value.id)
        .collect::<Vec<_>>();
    assert!(
        high_lanes.len() >= 2,
        "each cqo leaves the high half of a sign extension in RDX: {high_lanes:?}"
    );
    let homes = &artifact.certificates().stack_slots;
    assert!(
        homes.values().any(|slot| !slot.reload_values.is_empty()),
        "the homes are read back: {homes:#?}"
    );
    for slot in homes.values() {
        for lane in &high_lanes {
            assert!(
                !slot.reload_values.contains(*lane),
                "{lane:?} is a sign word, not the contents of the slot at {}",
                slot.offset
            );
        }
    }

    // The rendering never writes a parameter: both are read, only.
    let response = decompile(&machine.target(), &program, BASE).expect("decompile");
    let text = response.output.text();
    assert!(response.render_refusal.is_none(), "{text}");
    let signature = text
        .lines()
        .find(|line| line.contains("mul_div("))
        .expect("the signature");
    let parameters = signature
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(inside, _)| inside)
        .expect("a parameter list")
        .split(',')
        .filter_map(|parameter| parameter.split_whitespace().last())
        .map(|name| name.trim_start_matches('*').to_owned())
        .collect::<Vec<_>>();
    assert_eq!(parameters.len(), 2, "{signature}");
    for parameter in &parameters {
        let assigned = text.lines().any(|line| {
            line.trim_start()
                .strip_prefix(parameter.as_str())
                .is_some_and(|rest| rest.trim_start().starts_with("= "))
        });
        assert!(!assigned, "{parameter} is assigned:\n{text}");
    }
}

/// `long f(long *p, long *q, void (**g)(long *)) { long x = *p; (*g)(q); }`:
///
/// ```text
///   1000  mov rax, [rdi]     ; the first argument's first word
///   1003  mov rdi, rsi       ; the call is handed the second argument
///   1006  mov rax, [rdx]     ; the function pointer, through the third
///   1009  call rax
///   100b  ret
/// ```
const HANDS_ON_ITS_SECOND_ARGUMENT: &[u8] = &[
    0x48, 0x8b, 0x07, // 1000 mov rax, [rdi]
    0x48, 0x89, 0xf7, // 1003 mov rdi, rsi
    0x48, 0x8b, 0x02, // 1006 mov rax, [rdx]
    0xff, 0xd0, // 1009 call rax
    0xc3, // 100b ret
];

/// A call the summary cannot see into reaches through what it is handed and
/// nothing else. Emptying every argument's reach for it threw away the first
/// argument's eight bytes, which the call is never given: its register is
/// overwritten with the second argument before the call.
#[test]
fn an_unknown_call_leaves_the_reach_through_an_argument_it_is_not_handed() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let program = Fixture {
        bytes: HANDS_ON_ITS_SECOND_ARGUMENT.to_vec(),
        name: "hands_on",
    };
    let prepared = r2engine::native::prepared(&machine.target(), &program, BASE).expect("prepared");
    let shared = prepared.shared_artifact();
    let summary = r2ssa::PreparedCalleeSummary::derive(r2ssa::InterprocFunctionId(BASE), &shared)
        .expect("a summary");
    let reach = summary.argument_touch_reach();
    assert_eq!(
        reach.get(&0),
        Some(&r2ssa::ArgumentReach::from([
            r2ssa::SummaryArgumentReach::Bytes(8)
        ])),
        "{reach:?}"
    );
    // The second argument is handed to the call, which may touch any of it,
    // and so is the third: it is still in its register at the call, and a
    // callee no interface states the arity of may read every argument
    // register.
    assert!(
        reach
            .get(&1)
            .is_some_and(r2ssa::ArgumentReach::is_unbounded),
        "{reach:?}"
    );
    assert!(
        reach
            .get(&2)
            .is_some_and(r2ssa::ArgumentReach::is_unbounded),
        "{reach:?}"
    );
}

/// `long f(char *buf, void (*cb)(char **)) { char *local = buf; cb(&local); return *buf; }`:
///
/// ```text
///   1000  push rbx
///   1001  sub rsp, 0x10
///   1005  mov rbx, rdi           ; buf, kept across the call
///   1008  mov [rsp+8], rdi       ; local = buf
///   100d  lea rdi, [rsp+8]       ; the call is handed &local
///   1012  call rsi
///   1014  movsx rax, byte [rbx]  ; *buf
///   1018  add rsp, 0x10
///   101c  pop rbx
///   101d  ret
/// ```
const HANDS_ON_A_FRAME_OBJECT_HOLDING_ITS_FIRST_ARGUMENT: &[u8] = &[
    0x53, // 1000 push rbx
    0x48, 0x83, 0xec, 0x10, // 1001 sub rsp, 0x10
    0x48, 0x89, 0xfb, // 1005 mov rbx, rdi
    0x48, 0x89, 0x7c, 0x24, 0x08, // 1008 mov [rsp+8], rdi
    0x48, 0x8d, 0x7c, 0x24, 0x08, // 100d lea rdi, [rsp+8]
    0xff, 0xd6, // 1012 call rsi
    0x48, 0x0f, 0xbe, 0x03, // 1014 movsx rax, byte [rbx]
    0x48, 0x83, 0xc4, 0x10, // 1018 add rsp, 0x10
    0x5b, // 101c pop rbx
    0xc3, // 101d ret
];

/// A formal stored into a frame object whose address a call is handed reaches
/// that call as surely as the formal handed over itself: the callee reads the
/// object and writes through what it holds. The first argument is never in an
/// argument register at the call, so only the frame object carries it there,
/// and a reach of one byte through it would let the caller split an object
/// the callee may write anywhere in.
#[test]
fn a_formal_laundered_through_a_frame_object_a_call_is_handed_is_unbounded() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let program = Fixture {
        bytes: HANDS_ON_A_FRAME_OBJECT_HOLDING_ITS_FIRST_ARGUMENT.to_vec(),
        name: "launders",
    };
    let prepared = r2engine::native::prepared(&machine.target(), &program, BASE).expect("prepared");
    let shared = prepared.shared_artifact();
    let summary = r2ssa::PreparedCalleeSummary::derive(r2ssa::InterprocFunctionId(BASE), &shared)
        .expect("a summary");
    let reach = summary.argument_touch_reach();
    assert!(
        reach
            .get(&0)
            .is_some_and(r2ssa::ArgumentReach::is_unbounded),
        "{reach:?}"
    );
}

/// `long g(char *buf, long c, void (*cb)(char *)) { long x = buf[0]; if (c) buf += 1; cb(buf); return x; }`
/// at -O0: the call is handed a reload of `buf`'s home that two stores reach.
///
/// ```text
///   1000  push rbp; mov rbp, rsp; sub rsp, 0x20
///   1008  mov [rbp-8], rdi; mov [rbp-0x10], rsi; mov [rbp-0x18], rdx
///   1014  mov rax, [rbp-8]; movsx rax, byte [rax]; mov [rbp-0x20], rax
///   1020  cmp qword [rbp-0x10], 0; je 102c
///   1027  add qword [rbp-8], 1
///   102c  mov rax, [rbp-8]; mov rdi, rax     ; buf, from either store
///   1033  mov rax, [rbp-0x18]; call rax
///   1039  mov rax, [rbp-0x20]; leave; ret
/// ```
const HANDS_ON_A_MERGED_RELOAD_OF_ITS_FIRST_ARGUMENT: &[u8] = &[
    0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, // 1000
    0x48, 0x89, 0x7d, 0xf8, 0x48, 0x89, 0x75, 0xf0, 0x48, 0x89, 0x55, 0xe8, // 1008
    0x48, 0x8b, 0x45, 0xf8, 0x48, 0x0f, 0xbe, 0x00, 0x48, 0x89, 0x45, 0xe0, // 1014
    0x48, 0x83, 0x7d, 0xf0, 0x00, 0x74, 0x05, // 1020
    0x48, 0x83, 0x45, 0xf8, 0x01, // 1027
    0x48, 0x8b, 0x45, 0xf8, 0x48, 0x89, 0xc7, // 102c
    0x48, 0x8b, 0x45, 0xe8, 0xff, 0xd0, // 1033
    0x48, 0x8b, 0x45, 0xe0, 0xc9, 0xc3, // 1039
];

/// A load of the frame reads whatever was stored where it reads, whether or
/// not one store alone reaches it. The reload of `buf`'s home after the
/// branch is reached by the prologue's spill and by the increment, so no
/// reload certificate names one source; it is still `buf`, and the call it
/// is handed may touch any of `buf`'s object.
#[test]
fn a_frame_load_two_stores_reach_carries_the_formal_they_stored() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let program = Fixture {
        bytes: HANDS_ON_A_MERGED_RELOAD_OF_ITS_FIRST_ARGUMENT.to_vec(),
        name: "merged_reload",
    };
    let prepared = r2engine::native::prepared(&machine.target(), &program, BASE).expect("prepared");
    let shared = prepared.shared_artifact();
    let summary = r2ssa::PreparedCalleeSummary::derive(r2ssa::InterprocFunctionId(BASE), &shared)
        .expect("a summary");
    let reach = summary.argument_touch_reach();
    assert!(
        reach
            .get(&0)
            .is_some_and(r2ssa::ArgumentReach::is_unbounded),
        "{reach:?}"
    );
}

/// What the summary of the function at `entry` says it reaches through each
/// argument.
fn touch_reach_at(
    bytes: &[u8],
    name: &'static str,
    entry: u64,
) -> std::collections::BTreeMap<usize, r2ssa::ArgumentReach> {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let program = Fixture {
        bytes: bytes.to_vec(),
        name,
    };
    let prepared =
        r2engine::native::prepared(&machine.target(), &program, entry).expect("prepared");
    let shared = prepared.shared_artifact();
    r2ssa::PreparedCalleeSummary::derive(r2ssa::InterprocFunctionId(entry), &shared)
        .expect("a summary")
        .argument_touch_reach()
}

/// clang -O2 of `struct holder { char *p; long x; };`
/// `void ws(struct holder *h) { h->p[12] = 5; }` and
/// `void fstruct(char *buf) { struct holder h; h.p = buf; h.x = 0; buf[0] = 1; ws(&h); }`:
///
/// ```text
///   1000  sub rsp, 0x18
///   1004  mov [rsp+8], rdi          ; h.p = buf
///   1009  mov qword [rsp+0x10], 0   ; h.x = 0
///   1012  mov byte [rdi], 1         ; buf[0] = 1
///   1015  lea rdi, [rsp+8]          ; &h
///   101a  call 0x1030               ; ws
///   101f  add rsp, 0x18
///   1023  ret
///   1030  mov rax, [rdi]            ; ws: h->p
///   1033  mov byte [rax+0xc], 5     ;     h->p[12] = 5
///   1037  ret
/// ```
const HANDS_A_DIRECT_CALLEE_A_STRUCT_HOLDING_ITS_ARGUMENT: &[u8] = &[
    0x48, 0x83, 0xec, 0x18, // 1000 sub rsp, 0x18
    0x48, 0x89, 0x7c, 0x24, 0x08, // 1004 mov [rsp+8], rdi
    0x48, 0xc7, 0x44, 0x24, 0x10, 0x00, 0x00, 0x00, 0x00, // 1009 mov qword [rsp+0x10], 0
    0xc6, 0x07, 0x01, // 1012 mov byte [rdi], 1
    0x48, 0x8d, 0x7c, 0x24, 0x08, // 1015 lea rdi, [rsp+8]
    0xe8, 0x11, 0x00, 0x00, 0x00, // 101a call 0x1030
    0x48, 0x83, 0xc4, 0x18, // 101f add rsp, 0x18
    0xc3, // 1023 ret
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1024
    0x48, 0x8b, 0x07, // 1030 mov rax, [rdi]
    0xc6, 0x40, 0x0c, 0x05, // 1033 mov byte [rax+0xc], 5
    0xc3, // 1037 ret
];

/// A formal stored into a struct whose address a direct call is handed
/// reaches that callee: `ws` writes `buf[12]` through `h.p`. The body itself
/// touches `buf[0]` only, and a reach of one byte let the caller split its
/// buffer at the second byte.
#[test]
fn a_formal_stored_in_a_struct_a_direct_callee_is_handed_is_unbounded() {
    let reach = touch_reach_at(
        HANDS_A_DIRECT_CALLEE_A_STRUCT_HOLDING_ITS_ARGUMENT,
        "fstruct",
        BASE,
    );
    assert!(
        reach
            .get(&0)
            .is_some_and(r2ssa::ArgumentReach::is_unbounded),
        "{reach:?}"
    );
}

/// clang -O2 of `void wcont(long *x) { container_of(x, struct holder, x)->p[12] = 6; }`
/// and `void fcont(char *buf) { struct holder h; h.p = buf; h.x = 3; buf[0] = 1; wcont(&h.x); }`:
///
/// ```text
///   1000  sub rsp, 0x18
///   1004  mov [rsp+8], rdi          ; h.p = buf
///   1009  lea rax, [rsp+0x10]       ; &h.x
///   100e  mov qword [rsp+0x10], 3   ; h.x = 3
///   1017  mov byte [rdi], 1         ; buf[0] = 1
///   101a  mov rdi, rax
///   101d  call 0x1030               ; wcont(&h.x)
///   1022  add rsp, 0x18
///   1026  ret
///   1030  mov rax, [rdi-8]          ; wcont: h->p, eight bytes below x
///   1034  mov byte [rax+0xc], 6     ;        h->p[12] = 6
///   1038  ret
/// ```
const HANDS_A_DIRECT_CALLEE_THE_MEMBER_ABOVE_ITS_ARGUMENT: &[u8] = &[
    0x48, 0x83, 0xec, 0x18, // 1000 sub rsp, 0x18
    0x48, 0x89, 0x7c, 0x24, 0x08, // 1004 mov [rsp+8], rdi
    0x48, 0x8d, 0x44, 0x24, 0x10, // 1009 lea rax, [rsp+0x10]
    0x48, 0xc7, 0x44, 0x24, 0x10, 0x03, 0x00, 0x00, 0x00, // 100e mov qword [rsp+0x10], 3
    0xc6, 0x07, 0x01, // 1017 mov byte [rdi], 1
    0x48, 0x89, 0xc7, // 101a mov rdi, rax
    0xe8, 0x0e, 0x00, 0x00, 0x00, // 101d call 0x1030
    0x48, 0x83, 0xc4, 0x18, // 1022 add rsp, 0x18
    0xc3, // 1026 ret
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 1027
    0x48, 0x8b, 0x47, 0xf8, // 1030 mov rax, [rdi-8]
    0xc6, 0x40, 0x0c, 0x06, // 1034 mov byte [rax+0xc], 6
    0xc3, // 1038 ret
];

/// `container_of`: the callee is handed `&h.x` and reads `h.p` eight bytes
/// below it. A frame address that leaves the function says nothing about
/// where the object it names starts, so the formal stored below the address
/// handed out is as reachable as one above it.
#[test]
fn a_formal_stored_below_the_frame_address_a_direct_callee_is_handed_is_unbounded() {
    let reach = touch_reach_at(
        HANDS_A_DIRECT_CALLEE_THE_MEMBER_ABOVE_ITS_ARGUMENT,
        "fcont",
        BASE,
    );
    assert!(
        reach
            .get(&0)
            .is_some_and(r2ssa::ArgumentReach::is_unbounded),
        "{reach:?}"
    );
}

/// The callee's own reach: it reads eight bytes *below* the pointer it is
/// handed. A reach is a span upward from that pointer, and `[-8, -1]` is no
/// such span; taking its end alone stated `Bytes(0)`, that it touches none of
/// what it was handed.
#[test]
fn a_read_below_the_pointer_a_callee_is_handed_is_no_span_from_it() {
    let reach = touch_reach_at(
        HANDS_A_DIRECT_CALLEE_THE_MEMBER_ABOVE_ITS_ARGUMENT,
        "wcont",
        BASE + 0x30,
    );
    assert!(
        reach
            .get(&0)
            .is_some_and(r2ssa::ArgumentReach::is_unbounded),
        "{reach:?}"
    );
}

/// `long mn(long a, long b) { long sa = a, sb = b; long r = sa < sb ? sa : sb; return r + sa; }`
/// at clang -O0: the merge's two inputs are reloads of two other variables.
///
/// ```text
///   1000  push rbp; mov rbp, rsp
///   1004  mov [rbp-8], rdi; mov [rbp-0x10], rsi
///   100c  mov rax, [rbp-8];    mov [rbp-0x18], rax    ; sa
///   1014  mov rax, [rbp-0x10]; mov [rbp-0x20], rax    ; sb
///   101c  mov rax, [rbp-0x18]; cmp rax, [rbp-0x20]; jge 1037
///   102a  mov rax, [rbp-0x18]; mov [rbp-0x30], rax; jmp 103f
///   1037  mov rax, [rbp-0x20]; mov [rbp-0x30], rax
///   103f  mov rax, [rbp-0x30]; mov [rbp-0x28], rax
///   1047  mov rax, [rbp-0x28]; add rax, [rbp-0x18]; pop rbp; ret
/// ```
const SELECTS_BETWEEN_TWO_VARIABLES: &[u8] = &[
    0x55, 0x48, 0x89, 0xe5, // 1000
    0x48, 0x89, 0x7d, 0xf8, 0x48, 0x89, 0x75, 0xf0, // 1004
    0x48, 0x8b, 0x45, 0xf8, 0x48, 0x89, 0x45, 0xe8, // 100c
    0x48, 0x8b, 0x45, 0xf0, 0x48, 0x89, 0x45, 0xe0, // 1014
    0x48, 0x8b, 0x45, 0xe8, 0x48, 0x3b, 0x45, 0xe0, // 101c
    0x0f, 0x8d, 0x0d, 0x00, 0x00, 0x00, // 1024 jge 1037
    0x48, 0x8b, 0x45, 0xe8, 0x48, 0x89, 0x45, 0xd0, // 102a
    0xe9, 0x08, 0x00, 0x00, 0x00, // 1032 jmp 103f
    0x48, 0x8b, 0x45, 0xe0, 0x48, 0x89, 0x45, 0xd0, // 1037
    0x48, 0x8b, 0x45, 0xd0, 0x48, 0x89, 0x45, 0xd8, // 103f
    0x48, 0x8b, 0x45, 0xd8, 0x48, 0x03, 0x45, 0xe8, // 1047
    0x5d, 0xc3, // 104f
];

/// Two arms that each assign one variable from another become one assignment
/// of a conditional, and the merge each arm assigned is still the variable
/// the assignment writes. The arm's value marker used to be moved onto the
/// arm's right-hand side, which spells the *input's* variable, so the seal
/// read the merge as two bindings and refused the function.
#[test]
fn a_merge_of_two_variables_is_one_assignment_of_a_conditional() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let program = Fixture {
        bytes: SELECTS_BETWEEN_TWO_VARIABLES.to_vec(),
        name: "select",
    };
    let response = decompile(&machine.target(), &program, BASE).expect("decompile");
    let text = response.output.text();
    assert!(
        response.render_refusal.is_none(),
        "{:?}\n{text}",
        response.render_refusal
    );
    // One statement assigns the merge, choosing between the two variables.
    let selection = text
        .lines()
        .find(|line| line.contains(" ? "))
        .unwrap_or_else(|| panic!("no conditional assignment:\n{text}"));
    let (merge, choice) = selection
        .trim()
        .split_once(" = ")
        .unwrap_or_else(|| panic!("not an assignment: {selection}"));
    let (_, arms) = choice
        .split_once(" ? ")
        .unwrap_or_else(|| panic!("not a selection: {choice}"));
    let (then_arm, else_arm) = arms
        .trim_end_matches(';')
        .split_once(" : ")
        .unwrap_or_else(|| panic!("not two arms: {arms}"));
    assert_ne!(then_arm, else_arm, "{selection}");
    assert!(
        ![then_arm, else_arm].contains(&merge),
        "the merge is not one of its inputs: {selection}"
    );
    // And the return reads the merge it assigned.
    let returned = text
        .lines()
        .find(|line| line.trim_start().starts_with("return"))
        .unwrap_or_else(|| panic!("no return:\n{text}"));
    assert!(returned.contains(merge), "{returned}\n{text}");
}

/// ```text
///   1000  push rbx                     ; a save: the frame's, not a local's
///   1001  sub rsp, 0x20
///   1005  mov dword [rsp+0x10], 1
///   100d  mov dword [rsp+0x18], 2
///   1015  lea rdi, [rsp+0x10]
///   101a  call rsi                     ; nothing describes this callee
///   101c  mov eax, [rsp+0x18]
///   1020  add rsp, 0x20
///   1024  pop rbx
///   1025  ret
/// ```
const HANDS_A_BUFFER_TO_AN_UNKNOWN_CALL: &[u8] = &[
    0x53, // 1000 push rbx
    0x48, 0x83, 0xec, 0x20, // 1001 sub rsp, 0x20
    0xc7, 0x44, 0x24, 0x10, 0x01, 0x00, 0x00, 0x00, // 1005 mov dword [rsp+0x10], 1
    0xc7, 0x44, 0x24, 0x18, 0x02, 0x00, 0x00, 0x00, // 100d mov dword [rsp+0x18], 2
    0x48, 0x8d, 0x7c, 0x24, 0x10, // 1015 lea rdi, [rsp+0x10]
    0xff, 0xd6, // 101a call rsi
    0x8b, 0x44, 0x24, 0x18, // 101c mov eax, [rsp+0x18]
    0x48, 0x83, 0xc4, 0x20, // 1020 add rsp, 0x20
    0x5b, // 1024 pop rbx
    0xc3, // 1025 ret
];

/// A callee nothing describes, handed `&buf`, may reach anywhere in the object
/// `buf` is, and nothing states where that object ends: under the UB-free
/// premise it ends at the nearest slot no local extends across, here the
/// `rbx` save. So the word at +8 is a member of what the call was handed, not
/// a neighbour the call cannot touch. Splitting them let a rendering keep the
/// constant 2 across the call, which the callee may have overwritten.
#[test]
fn a_buffer_an_unknown_call_is_handed_runs_to_the_nearest_save_slot() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let program = Fixture {
        bytes: HANDS_A_BUFFER_TO_AN_UNKNOWN_CALL.to_vec(),
        name: "hands_a_buffer",
    };
    let prepared = r2engine::native::prepared(&machine.target(), &program, BASE).expect("prepared");
    let artifact = prepared.shared_artifact();
    let graph = artifact.graph();
    let objects = artifact.objects();
    let object_stored_at = |instruction: u64| {
        graph
            .insts_for_instruction(instruction)
            .iter()
            .find_map(|inst| match &graph.inst(*inst)?.payload {
                InstPayload::Op(SSAOp::Store { addr, space, .. }) => {
                    objects.object_for_value(*addr, *space)
                }
                _ => None,
            })
            .expect("the instruction stores to an object")
    };
    let first = object_stored_at(BASE + 0x05);
    let second = object_stored_at(BASE + 0x0d);
    let save = object_stored_at(BASE);
    assert_eq!(first, second, "{:#?}", objects.stack_objects);
    assert_ne!(first, save, "{:#?}", objects.stack_objects);
}

/// clang -O0's `return *rows[index];`: both formals are spilled to their homes
/// and reloaded, and `index` is the `esi` lane of `rsi`.
///
/// ```text
///   1000  push rbp ; mov rbp, rsp
///   1004  mov [rbp - 8], rdi ; mov [rbp - 0xc], esi
///   100b  mov rax, [rbp - 8] ; mov ecx, [rbp - 0xc]
///   1012  mov rax, [rax + rcx*8] ; mov rax, [rax]
///   1019  pop rbp ; ret
/// ```
const INDEXED_THROUGH_HOMES: &[u8] = &[
    0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0xf8, 0x89, 0x75, 0xf4, 0x48, 0x8b, 0x45, 0xf8, 0x8b,
    0x4d, 0xf4, 0x48, 0x8b, 0x04, 0xc8, 0x48, 0x8b, 0x00, 0x5d, 0xc3,
];

/// Once the homes are promoted, the index is `zext(esi)`. The formal is the
/// `esi` lane, minted after the value view was first solved, so the view must
/// name the lane by the bits of `rsi` it is -- otherwise the reach through
/// `rows` loses its stride and becomes unbounded, and every caller merges its
/// frame into one object.
#[test]
fn a_reach_indexed_by_a_lane_formal_keeps_its_stride() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let program = Fixture {
        bytes: INDEXED_THROUGH_HOMES.to_vec(),
        name: "indirect_load",
    };
    let prepared = r2engine::native::prepared(&machine.target(), &program, BASE).expect("prepared");
    let shared = prepared.shared_artifact();
    let summary = r2ssa::PreparedCalleeSummary::derive(r2ssa::InterprocFunctionId(BASE), &shared)
        .expect("a summary");
    let reach = summary.argument_touch_reach();
    let rows = reach.get(&0).expect("a reach through rows");
    assert!(!rows.is_unbounded(), "{reach:?}");
    assert!(
        rows.terms().any(|term| matches!(
            term,
            r2ssa::SummaryArgumentReach::Scaled {
                argument: 1,
                stride: 8,
                ..
            }
        )),
        "{reach:?}"
    );
}

/// clang -O0's `static int zero_of(int q) { return q ^ q; }`: the home is
/// promoted, so both reads are the parameter and `q ^ q` rewrites to `0`.
/// Nothing reads the parameter by name any more; its declaration is its one
/// occurrence, and the function renders rather than refusing.
#[test]
fn a_parameter_every_read_of_which_is_rewritten_away_is_still_declared() {
    // push rbp; mov rbp, rsp; mov [rbp-4], edi; mov eax, [rbp-4];
    // xor eax, [rbp-4]; pop rbp; ret
    const ZERO_OF: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xfc, 0x8b, 0x45, 0xfc, 0x33, 0x45, 0xfc, 0x5d, 0xc3,
        0x00,
    ];
    let machine = Machine::new("x86-64", "x86-64", 64);
    let program = Fixture {
        bytes: ZERO_OF.to_vec(),
        name: "zero_of",
    };
    let response = decompile(&machine.target(), &program, BASE).expect("decompile");
    assert!(
        response.render_refusal.is_none(),
        "{:?}",
        response.render_refusal
    );
    let output = response.output.text();
    assert!(output.contains("return 0;"), "{output}");
}

/// A stack-protector check around a call: the canary is read through the
/// thread pointer before the call and again after it. The callee calls
/// through a register, so its own body proves nothing about `fs` either.
const CANARY_AROUND_A_CALL: &[u8] = &[
    0x48, 0x83, 0xec, 0x18, // 1000 sub rsp, 0x18
    0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, // 1004 mov rax, fs:[0x28]
    0x48, 0x89, 0x44, 0x24, 0x08, // 100d mov [rsp+8], rax
    0xe8, 0x19, 0x00, 0x00, 0x00, // 1012 call 0x1030
    0x48, 0x8b, 0x44, 0x24, 0x08, // 1017 mov rax, [rsp+8]
    0x64, 0x48, 0x2b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, // 101c sub rax, fs:[0x28]
    0x48, 0x83, 0xc4, 0x18, // 1025 add rsp, 0x18
    0xc3, // 1029 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 102a padding
    0xff, 0xd7, // 1030 call rdi
    0xc3, // 1032 ret
];

/// Every `FS_OFFSET_<n>` a rendering names.
fn thread_pointer_versions(text: &str) -> BTreeSet<String> {
    text.match_indices("FS_OFFSET_")
        .map(|(at, _)| {
            text[at..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect::<String>()
        })
        .collect()
}

/// The platform reserves the thread pointer to the system, so no call is a
/// definition of it: both reads of the canary go through the one value the
/// function entered with. The convention's lists say nothing about `fs`, and
/// before the platform's table was read the call redefined it, so the second
/// read named a register nothing ever assigned.
#[test]
fn a_call_does_not_redefine_the_register_the_platform_reserves() {
    let machine = Machine::on("x86-64", "x86-64", 64, Platform::Linux);
    let program = Fixture {
        bytes: CANARY_AROUND_A_CALL.to_vec(),
        name: "canary",
    };
    let response = decompile(&machine.target(), &program, BASE).expect("decompile");
    assert_eq!(
        thread_pointer_versions(response.output.text()),
        BTreeSet::from(["FS_OFFSET_0".to_owned()]),
        "{}",
        response.output
    );
    // Without the platform the convention alone decides, and it calls the
    // register clobbered: that is the precision the table buys.
    let unknown = Machine::new("x86-64", "x86-64", 64);
    let without = decompile(&unknown.target(), &program, BASE).expect("decompile");
    assert!(
        thread_pointer_versions(without.output.text()).contains("FS_OFFSET_1"),
        "{}",
        without.output
    );
}

/// A stack-protector check: the canary is stored from `fs:[0x28]`, reloaded, compared with a
/// second read of the guard, and a mismatch calls a function that never returns.
const CANARY_CHECKED: &[u8] = &[
    0x48, 0x83, 0xec, 0x18, // 1000 sub rsp, 0x18
    0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, // 1004 mov rax, fs:[0x28]
    0x48, 0x89, 0x44, 0x24, 0x08, // 100d mov [rsp+8], rax
    0x31, 0xc0, // 1012 xor eax, eax
    0x48, 0x8b, 0x54, 0x24, 0x08, // 1014 mov rdx, [rsp+8]
    0x64, 0x48, 0x2b, 0x14, 0x25, 0x28, 0x00, 0x00, 0x00, // 1019 sub rdx, fs:[0x28]
    0x75, 0x05, // 1022 jne 0x1029
    0x48, 0x83, 0xc4, 0x18, // 1024 add rsp, 0x18
    0xc3, // 1028 ret
    0xe8, 0x02, 0x00, 0x00, 0x00, // 1029 call 0x1030
    0x90, 0x90, // 102e padding
    0xeb, 0xfe, // 1030 jmp 0x1030
];

/// Under `Premise::UbFreeSource` the canary still holds the guard, so the check passes: the
/// rendering reads no thread pointer, calls nothing, and says which premise it assumed.
#[test]
fn a_stack_protector_check_is_compiler_inserted_under_a_ub_free_source() {
    let machine = Machine::on("x86-64", "x86-64", 64, Platform::Linux);
    let program = Halting {
        fixture: Fixture {
            bytes: CANARY_CHECKED.to_vec(),
            name: "canary_checked",
        },
        halts: 0x1030,
    };
    let response = decompile(&machine.target(), &program, BASE).expect("decompile");
    let output = response.output.text();
    assert!(thread_pointer_versions(output).is_empty(), "{output}");
    assert!(output.contains("return 0;"), "{output}");
    assert!(!output.contains("fcn_1030"), "{output}");
    assert!(
        output.contains("compiler-inserted (assuming ub-free)"),
        "{output}"
    );
    // The analysis says what it decided under, whatever the ledger keeps of the check.
    assert_eq!(
        response.premises,
        std::collections::BTreeSet::from([r2source::Premise::UbFreeSource])
    );
}

/// The slot is written again before the check, so the check can fail and stays a residual.
#[test]
fn a_canary_written_twice_is_not_decided() {
    let mut bytes = CANARY_CHECKED[..0x14].to_vec();
    bytes.extend([0x48, 0x89, 0x44, 0x24, 0x08]); // 1014 mov [rsp+8], rax
    bytes.extend(&CANARY_CHECKED[0x14..0x22]); // 1019 the reload and compare
    bytes.extend([0x75, 0x05]); // 1027 jne 0x102e
    bytes.extend(&CANARY_CHECKED[0x24..0x29]); // 1029 add rsp; ret
    bytes.extend([0xe8, 0x02, 0x00, 0x00, 0x00, 0x90, 0x90, 0xeb, 0xfe]); // 102e call 0x1035
    let machine = Machine::on("x86-64", "x86-64", 64, Platform::Linux);
    let program = Halting {
        fixture: Fixture {
            bytes,
            name: "canary_overwritten",
        },
        halts: 0x1035,
    };
    let response = decompile(&machine.target(), &program, BASE).expect("decompile");
    let output = response.output.text();
    assert!(output.contains("FS_OFFSET_0"), "{output}");
    assert!(!output.contains("compiler-inserted"), "{output}");
    assert!(response.premises.is_empty(), "{:?}", response.premises);
}

/// Two reads of a thread-local variable at `fs:[0x30]` compared the same way are a program's
/// own check: a call between may change the variable, and only `fs:[0x28]` is the platform's guard.
#[test]
fn a_thread_local_read_twice_is_no_stack_guard() {
    let mut bytes = CANARY_CHECKED.to_vec();
    bytes[0x09] = 0x30; // 1004 mov rax, fs:[0x30]
    bytes[0x1e] = 0x30; // 1019 sub rdx, fs:[0x30]
    let machine = Machine::on("x86-64", "x86-64", 64, Platform::Linux);
    let program = Halting {
        fixture: Fixture {
            bytes,
            name: "thread_local_checked",
        },
        halts: 0x1030,
    };
    let response = decompile(&machine.target(), &program, BASE).expect("decompile");
    let output = response.output.text();
    assert!(output.contains("FS_OFFSET_0"), "{output}");
    assert!(!output.contains("compiler-inserted"), "{output}");
}

/// The canary is still in RAX at `ret`, so the function returns the guard: that read is the
/// program's and keeps its residual, while the check and the slot are still the compiler's.
#[test]
fn a_canary_the_function_returns_keeps_its_read() {
    let mut bytes = CANARY_CHECKED.to_vec();
    bytes[0x12..0x14].copy_from_slice(&[0x90, 0x90]); // 1012 no `xor eax, eax`
    let machine = Machine::on("x86-64", "x86-64", 64, Platform::Linux);
    let program = Halting {
        fixture: Fixture {
            bytes,
            name: "canary_returned",
        },
        halts: 0x1030,
    };
    let response = decompile(&machine.target(), &program, BASE).expect("decompile");
    let output = response.output.text();
    assert!(output.contains("FS_OFFSET_0"), "{output}");
    assert!(!output.contains("fcn_1030"), "{output}");
    assert!(output.contains("compiler-inserted"), "{output}");
}

/// The failure path calls a function that returns, so nothing proves the check is a protector.
#[test]
fn a_check_whose_failure_returns_is_not_decided() {
    let bytes = CANARY_CHECKED.to_vec();
    let machine = Machine::on("x86-64", "x86-64", 64, Platform::Linux);
    let program = Fixture {
        bytes,
        name: "canary_returning_failure",
    };
    let response = decompile(&machine.target(), &program, BASE).expect("decompile");
    let output = response.output.text();
    assert!(output.contains("FS_OFFSET_0"), "{output}");
    assert!(!output.contains("compiler-inserted"), "{output}");
}

/// `mul_div` from `tests/gold/review.c` at gcc -O0: `a * 7 / b + a % b`, with
/// `a` and `b` spilled to the frame and reloaded for each division.
const DIVIDE_AFTER_RELOAD: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, // 1000 endbr64
    0x55, // 1004 push rbp
    0x48, 0x89, 0xe5, // 1005 mov rbp, rsp
    0x48, 0x89, 0x7d, 0xf8, // 1008 mov [rbp-8], rdi
    0x48, 0x89, 0x75, 0xf0, // 100c mov [rbp-0x10], rsi
    0x48, 0x83, 0x7d, 0xf0, 0x00, // 1010 cmp qword [rbp-0x10], 0
    0x75, 0x07, // 1015 jne 0x101e
    0xb8, 0x00, 0x00, 0x00, 0x00, // 1017 mov eax, 0
    0xeb, 0x27, // 101c jmp 0x1045
    0x48, 0x8b, 0x55, 0xf8, // 101e mov rdx, [rbp-8]
    0x48, 0x89, 0xd0, // 1022 mov rax, rdx
    0x48, 0xc1, 0xe0, 0x03, // 1025 shl rax, 3
    0x48, 0x29, 0xd0, // 1029 sub rax, rdx
    0x48, 0x99, // 102c cqo
    0x48, 0xf7, 0x7d, 0xf0, // 102e idiv qword [rbp-0x10]
    0x48, 0x89, 0xc1, // 1032 mov rcx, rax
    0x48, 0x8b, 0x45, 0xf8, // 1035 mov rax, [rbp-8]
    0x48, 0x99, // 1039 cqo
    0x48, 0xf7, 0x7d, 0xf0, // 103b idiv qword [rbp-0x10]
    0x48, 0x89, 0xd0, // 103f mov rax, rdx
    0x48, 0x01, 0xc8, // 1042 add rax, rcx
    0x5d, // 1045 pop rbp
    0xc3, // 1046 ret
];

/// The second division's dividend is `a` reloaded from its slot, and `cqo`
/// then writes the reload's sign into `rdx`, which the slot's variable also
/// holds. Read through that variable after the sign was written into it, the
/// reload is stale: the remainder divided the sign word by `b` twice over and
/// returned `a * 7 / b` plus nonsense. Either the reload reads its own value --
/// promotion makes the home a variable, so there is no reload left -- or the
/// reaching-values check gives it a variable of its own; whichever, the
/// function computes what the machine does, which is what is run here.
#[test]
fn a_reload_read_after_its_variable_is_overwritten_gets_a_variable_of_its_own() {
    let text = rendered(DIVIDE_AFTER_RELOAD, "mul_div");
    run_rendered(
        "mul_div",
        &text,
        r#"int main(void) {
    const int64_t cases[][2] = {{7, 3}, {-7, 3}, {100, -9}, {0, 5}, {5, 0}, {-1, 1}};
    for (int i = 0; i < 6; i++) {
        int64_t a = cases[i][0], b = cases[i][1];
        int64_t want = b == 0 ? 0 : a * 7 / b + a % b;
        if ((int64_t)mul_div((uint64_t)a, (uint64_t)b) != want) {
            return 1 + i;
        }
    }
    return 0;
}"#,
    );
}

/// `rbx` pushed and popped around a frame whose buffer is indexed by a byte
/// nothing bounds below 0xf8: the index's reach covers the slot `rbx` is saved
/// in, and the return address beyond it.
const SAVE_BESIDE_AN_INDEXED_BUFFER: &[u8] = &[
    0x53, // 1000 push rbx
    0x48, 0x83, 0xec, 0x60, // 1001 sub rsp, 0x60
    0x89, 0xf8, // 1005 mov eax, edi
    0x25, 0xf8, 0x00, 0x00, 0x00, // 1007 and eax, 0xf8
    0x40, 0x88, 0x34, 0x04, // 100c mov [rsp+rax], sil
    0x0f, 0xb6, 0x04, 0x24, // 1010 movzx eax, byte [rsp]
    0x48, 0x83, 0xc4, 0x60, // 1014 add rsp, 0x60
    0x5b, // 1018 pop rbx
    0xc3, // 1019 ret
];

/// The convention makes the callee put `rbx` back, and it puts it back from
/// the slot it pushed it to, so no store of the program's lands there: that
/// slot is the compiler's, however far the buffer's index is proved to reach.
/// Before the save was evidence an object ends there, the buffer's recovered
/// extent absorbed it, and the push rendered as a store of `rbx`'s entry
/// value into the buffer, a residual held from entry.
#[test]
fn a_register_saved_beside_an_indexed_buffer_is_no_store_of_the_program() {
    let text = rendered(SAVE_BESIDE_AN_INDEXED_BUFFER, "indexed_store");
    assert!(!text.contains("r2sleigh_residual"), "{text}");
    assert!(!text.contains("RBX_0"), "{text}");
    assert!(text.contains("= SIL_0;"), "{text}");
}

/// gcc -O1 `bool_relay(m, n)`: `setg al` writes one byte of RAX, and the
/// only reader keeps that byte (`or %ecx,%eax` then `movzbl %al`).
const SETCC_INTO_AN_ENTRY_REGISTER: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, // 1000 endbr64
    0x85, 0xff, // 1004 test edi, edi
    0x0f, 0x9f, 0xc0, // 1006 setg al
    0x85, 0xf6, // 1009 test esi, esi
    0x0f, 0x9f, 0xc1, // 100b setg cl
    0x84, 0xc0, // 100e test al, al
    0x74, 0x09, // 1010 je 0x101b
    0xba, 0x02, 0x00, 0x00, 0x00, // 1012 mov edx, 2
    0x84, 0xc9, // 1017 test cl, cl
    0x75, 0x05, // 1019 jne 0x1020
    0x09, 0xc8, // 101b or eax, ecx
    0x0f, 0xb6, 0xd0, // 101d movzx edx, al
    0x89, 0xd0, // 1020 mov eax, edx
    0xc3, // 1022 ret
];

/// The seven bytes `setg al` leaves in RAX are the caller's, and nothing
/// reads them: the demanded-bytes fact says the INSERT reads none of its
/// base, so the entry value of RAX is no input and nothing renders a read of
/// a value no statement assigned. Before, it rendered as a residual trap.
#[test]
fn a_lane_write_whose_other_bytes_nobody_reads_does_not_read_them() {
    let text = rendered(SETCC_INTO_AN_ENTRY_REGISTER, "bool_relay");
    assert!(!text.contains("r2sleigh_residual"), "{text}");
    run_rendered(
        "bool_relay",
        &text,
        r#"int main(void) {
    const int cases[][2] = {{1, 1}, {1, 0}, {0, 1}, {0, 0}, {-3, 4}, {5, -2}};
    for (int i = 0; i < 6; i++) {
        int m = cases[i][0], n = cases[i][1];
        int a = m > 0, b = n > 0;
        int want = (a && b) ? 2 : (a || b) ? 1 : 0;
        if ((int)bool_relay(m, n) != want) {
            return 1 + i;
        }
    }
    return 0;
}"#,
    );
}

/// `mov rdi, rsi; call 0x1010; ret`, and at 0x1010 `mov rax, rdi; ret`.
const COPY_INTO_AN_ARGUMENT: &[u8] = &[
    0x48, 0x89, 0xf7, // 0x1000 mov rdi, rsi
    0xe8, 0x08, 0x00, 0x00, 0x00, // 0x1003 call 0x1010
    0xc3, // 0x1008 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // padding to 0x1010
    0x48, 0x89, 0xf8, // 0x1010 mov rax, rdi
    0xc3, // 0x1013 ret
];

/// The boundary passes the value that reached `rdi`, the copy; copy
/// forwarding leaves the call reading `rsi`, the value the copy carried. The
/// two have one class of bits, so the call's read of `rsi` is a read the text
/// performs, and liveness must not ignore it.
#[test]
fn a_call_reading_the_value_its_copied_argument_carried_reads_it() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let program = ImportCaller {
        bytes: COPY_INTO_AN_ARGUMENT,
        stub: 0x1010,
    };
    let prepared = r2engine::native::prepared(&machine.target(), &program, BASE).expect("prepared");
    let artifact: &r2ssa::SsaArtifact = prepared.artifact();
    let graph = artifact.graph();
    let calls = &artifact.facts().boundaries.calls;
    let call = calls.values().next().expect("the call");
    let r2ssa::SourceCallArgumentValue::Value(passed) = call
        .arguments
        .first()
        .unwrap_or_else(|| panic!("{call:#?}\n{}", artifact.function().dump()))
        .value
    else {
        panic!("the first argument is a value: {call:#?}");
    };
    let passed = &graph.value(passed).expect("a value").var;
    let Some(SSAOp::Copy { src, .. }) = graph.defining_op(passed) else {
        panic!("the argument is the copy: {passed:?}");
    };
    let carried = *src;
    let call_reads = graph
        .use_sites(carried)
        .iter()
        .filter(|site| {
            matches!(
                graph.inst(site.inst).map(|inst| &inst.payload),
                Some(InstPayload::Op(SSAOp::CallUse { .. }))
            )
        })
        .collect::<Vec<_>>();
    assert!(!call_reads.is_empty(), "{}", artifact.function().dump());
    for site in call_reads {
        assert!(
            !artifact.ignored_reads().contains(site),
            "{site:?} is the argument's read\n{}",
            artifact.function().dump()
        );
    }
}

/// `fnv1a32` from `tests/coverage/pinned/hashes_gcc_x64_O2`, gcc -O2:
/// `for (i = 0; i < len; i++) { h ^= data[i]; h *= 16777619; }`.
const FNV1A32_O2: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
    0x48, 0x85, 0xf6, // test rsi, rsi
    0x74, 0x27, // je 0x30
    0x48, 0x01, 0xfe, // add rsi, rdi
    0xb8, 0xc5, 0x9d, 0x1c, 0x81, // mov eax, 0x811c9dc5
    0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00, // nop
    0x0f, 0xb6, 0x17, // 0x18 movzx edx, byte [rdi]
    0x48, 0x83, 0xc7, 0x01, // add rdi, 1
    0x31, 0xd0, // xor eax, edx
    0x69, 0xc0, 0x93, 0x01, 0x00, 0x01, // imul eax, eax, 0x1000193
    0x48, 0x39, 0xfe, // cmp rsi, rdi
    0x75, 0xec, // jne 0x18
    0xc3, // ret
    0x0f, 0x1f, 0x00, // nop
    0xb8, 0xc5, 0x9d, 0x1c, 0x81, // 0x30 mov eax, 0x811c9dc5
    0xc3, // ret
];

/// A merge is placed only where some byte of its storage is live on entry
/// (issue #56). The loop carries the hash and the pointer; every flag the
/// compare sets is written again before it is read, no Sleigh temporary
/// outlives its instruction, and the `movzx` writes the four bytes of `rdx`
/// the `xor` reads before anything reads them, so none of those merges.
#[test]
fn a_loop_header_merges_only_what_the_loop_carries() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let program = Fixture {
        bytes: FNV1A32_O2.to_vec(),
        name: "fnv1a32",
    };
    let prepared = r2engine::native::prepared(&machine.target(), &program, BASE).expect("prepared");
    let function = prepared.artifact().function();
    let header = function
        .get_block(BASE + 0x18)
        .unwrap_or_else(|| panic!("the loop header\n{}", function.dump()));
    let merged = header
        .phis()
        .iter()
        .map(|phi| function.var(phi.dst).display_name())
        .collect::<Vec<_>>();
    assert_eq!(merged, ["RAX_2", "RDI_1"], "{}", function.dump());
}

/// clang -O1's `classify`: a switch over 0..=7 lowered to a lookup in an
/// `int[8]` at `LOOKUP`, or -1 above it.
///
/// ```text
/// mov eax, 0xffffffff
/// cmp edi, 7
/// ja  done
/// mov eax, edi
/// mov eax, dword [LOOKUP + rax*4]
/// done: ret
/// ```
const LOOKUP: u64 = 0x2068;
const CLASSIFY: &[u8] = &[
    0xb8, 0xff, 0xff, 0xff, 0xff, // mov eax, -1
    0x83, 0xff, 0x07, // cmp edi, 7
    0x77, 0x09, // ja +9
    0x89, 0xf8, // mov eax, edi
    0x8b, 0x04, 0x85, 0x68, 0x20, 0x00, 0x00, // mov eax, [rax*4 + 0x2068]
    0xc3, // ret
];
/// The table's eight words. The first is 10 -- `0a 00 00 00` -- so its
/// first two bytes read as the text "\n", which is what the string scan
/// finds there.
const LOOKUP_BYTES: [u8; 32] = [
    10, 0, 0, 0, 21, 0, 0, 0, 32, 0, 0, 0, 43, 0, 0, 0, 54, 0, 0, 0, 65, 0, 0, 0, 0xff, 0xff, 0xff,
    0xff, 87, 0, 0, 0,
];

/// `CLASSIFY` as code and `LOOKUP_BYTES` as static data at `LOOKUP`.
struct LookupTable;

impl r2engine::body::Program for LookupTable {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let region = self.region(vaddr)?;
        let bytes: &[u8] = match region.execute {
            true => CLASSIFY,
            false => &LOOKUP_BYTES,
        };
        let rest = bytes.get(usize::try_from(vaddr - region.start).ok()?..)?;
        Some(rest[..rest.len().min(max)].to_vec())
    }

    fn region(&self, vaddr: u64) -> Option<r2engine::body::Region> {
        let end = LOOKUP + LOOKUP_BYTES.len() as u64;
        code_region(CLASSIFY.len(), vaddr).or_else(|| {
            (LOOKUP..end)
                .contains(&vaddr)
                .then_some(r2engine::body::Region {
                    start: LOOKUP,
                    end,
                    file_end: end,
                    execute: false,
                    write: false,
                })
        })
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        vaddr == BASE
    }
}

impl Program for LookupTable {
    fn holds_static_data(&self, vaddr: u64) -> bool {
        (LOOKUP..LOOKUP + LOOKUP_BYTES.len() as u64).contains(&vaddr)
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

/// An address the function computes with is a number, whatever text its
/// first bytes happen to spell: the table is read a word at a time at
/// `LOOKUP + 4 * x`, and a string literal there would be two bytes the
/// compiler places somewhere else, so the read would leave it.
#[test]
fn the_base_of_an_indexed_word_read_is_no_string_literal() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let response = decompile(&target, &LookupTable, BASE).expect("decompile");
    let text = response.output.text().to_string();
    assert!(response.render_refusal.is_none(), "{text}");
    assert!(
        !text.contains("\"\\n\""),
        "the table's address is spelled as text: {text}"
    );
    assert!(
        text.contains("0x2068"),
        "the table is read at its own address: {text}"
    );
}

/// `dl` written on both arms of a branch and read back after they merge:
/// only the byte `sete` wrote is read, so the caller's `rdx` is no input of
/// the function. The merge is what keeps the read from folding into the
/// write.
const SETE_LOW_BYTE: &[u8] = &[
    0x48, 0x85, 0xff, // 0x1000 test rdi, rdi
    0x0f, 0x94, 0xc2, // 0x1003 sete dl
    0x74, 0x08, // 0x1006 je 0x1010
    0x48, 0x85, 0xf6, // 0x1008 test rsi, rsi
    0x0f, 0x94, 0xc2, // 0x100b sete dl
    0x90, 0x90, // 0x100e nop; nop
    0x0f, 0xb6, 0xc2, // 0x1010 movzx eax, dl
    0xc3, // 0x1013 ret
];

/// The convention's argument registers are construction's carriers, so
/// `sete dl` writes the low byte of the whole `rdx`, and the bytes above it
/// are the caller's. Reading back the byte it wrote reads none of those: a
/// parameter is an entry register some byte of which an observation reaches,
/// and here only `rdi` is.
#[test]
fn a_lane_written_and_read_back_is_no_parameter() {
    let text = rendered(SETE_LOW_BYTE, "is_null");
    let signature = text.lines().next().expect("a signature");
    let parameters = signature
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(list, _)| list)
        .expect("a parameter list");
    assert_eq!(
        parameters, "uint64_t RDI_0, uint64_t RSI_0",
        "the signature names a register the function never reads: {text}"
    );
}

/// `f` is called in a loop with `rsi = 1` and `rdi` the last result, or the
/// pointer itself on the first pass: the body writes `rsi`, and `rdi` merges.
const LOOPED_INDIRECT_CALL: &[u8] = &[
    0x53, // 0x1000 push rbx
    0x48, 0x89, 0xfb, // 0x1001 mov rbx, rdi
    0x48, 0xc7, 0xc6, 0x01, 0x00, 0x00, 0x00, // 0x1004 mov rsi, 1
    0xff, 0xd3, // 0x100b call rbx
    0x48, 0x89, 0xc7, // 0x100d mov rdi, rax
    0x48, 0x85, 0xc0, // 0x1010 test rax, rax
    0x75, 0xef, // 0x1013 jne 0x1004
    0x5b, // 0x1015 pop rbx
    0xc3, // 0x1016 ret
];

/// A call whose first argument slot the scan cannot see, while the body
/// writes the second, passes an unproven count: it is never a call of none.
#[test]
fn an_unseen_argument_below_a_written_one_leaves_the_call_unrendered() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: LOOPED_INDIRECT_CALL.to_vec(),
        name: "looped",
    };
    let response = decompile(&target, &program, BASE).expect("decompile");
    let text = response.output.text();
    assert!(!text.contains("(void))"), "{text}");
    assert!(
        response.render_refusal.is_some() || text.contains("r2sleigh_residual"),
        "{text}"
    );
}

/// `f` hands `rdi` on unchanged to a call through memory and adds `rsi` to its
/// result; `main` calls it with `edi = 3, esi = 5`.
const READS_PAST_ITS_PARAMETERS: &[u8] = &[
    0x53, // 0x1000 push rbx
    0x48, 0x89, 0xf3, // 0x1001 mov rbx, rsi
    0xff, 0x14, 0x25, 0x00, 0x20, 0x00, 0x00, // 0x1004 call [0x2000]
    0x48, 0x01, 0xd8, // 0x100b add rax, rbx
    0x5b, // 0x100e pop rbx
    0xc3, // 0x100f ret
    0xbf, 0x03, 0x00, 0x00, 0x00, // 0x1010 mov edi, 3
    0xbe, 0x05, 0x00, 0x00, 0x00, // 0x1015 mov esi, 5
    0xe8, 0xe1, 0xff, 0xff, 0xff, // 0x101a call 0x1000
    0xc3, // 0x101f ret
];

/// A callee whose parameters are a floor mints no contract; a call to it takes what the caller
/// provably wrote, at least the floor: `past(3, 5)` (doc/adr-resolved-bodies.md, "Demand").
#[test]
fn a_callee_whose_parameters_are_a_floor_takes_what_its_caller_wrote() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: READS_PAST_ITS_PARAMETERS.to_vec(),
        name: "past",
    };
    let response = decompile(&target, &program, BASE + 0x10).expect("decompile");
    let text = response.output.text();
    assert!(text.contains("past(3, 5)"), "{text}");
}

/// `f` hands every argument register on unread to a call through memory; the caller writes `edi`
/// and, on one of two paths each, `esi`.
const AN_ARGUMENT_MERGED_FROM_TWO_WRITES: &[u8] = &[
    0xff, 0x14, 0x25, 0x00, 0x20, 0x00, 0x00, // 0x1000 call [0x2000]
    0xb8, 0x07, 0x00, 0x00, 0x00, // 0x1007 mov eax, 7
    0xc3, // 0x100c ret
    0xcc, 0xcc, 0xcc, // 0x100d padding
    0x85, 0xff, // 0x1010 test edi, edi
    0x74, 0x07, // 0x1012 je 0x101b
    0xbe, 0x05, 0x00, 0x00, 0x00, // 0x1014 mov esi, 5
    0xeb, 0x05, // 0x1019 jmp 0x1020
    0xbe, 0x07, 0x00, 0x00, 0x00, // 0x101b mov esi, 7
    0xbf, 0x03, 0x00, 0x00, 0x00, // 0x1020 mov edi, 3
    0xe8, 0xd6, 0xff, 0xff, 0xff, // 0x1025 call 0x1000
    0xc3, // 0x102a ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 0x102b padding
];

/// Past the callee's floor, a slot the count cannot see but the caller writes on some path may be
/// an argument: the call is a residual, never `merged(3)` without the `esi` it was handed.
#[test]
fn an_argument_merged_from_two_writes_past_the_floor_refuses_the_count() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: AN_ARGUMENT_MERGED_FROM_TWO_WRITES.to_vec(),
        name: "merged",
    };
    let response = decompile(&target, &program, BASE + 0x10).expect("decompile");
    let text = response.output.text();
    assert!(!text.contains("merged(3)"), "{text}");
    assert!(
        response.render_refusal.is_some() || text.contains("r2sleigh_residual"),
        "{text}"
    );
}

/// `f(a, b)` calls itself with `(a - 1, b + 1)`, passing `b + 1` through `rdx`
/// on the way to `rsi`, and returns `b` or zero.
const SELF_CALL_WITH_A_SCRATCH_REGISTER: &[u8] = &[
    0x48, 0x85, 0xff, // 0x1000 test rdi, rdi
    0x74, 0x12, // 0x1003 je 0x1017
    0x48, 0x8d, 0x56, 0x01, // 0x1005 lea rdx, [rsi + 1]
    0x48, 0xff, 0xcf, // 0x1009 dec rdi
    0x48, 0x89, 0xd6, // 0x100c mov rsi, rdx
    0xe8, 0xec, 0xff, 0xff, 0xff, // 0x100f call 0x1000
    0x31, 0xc0, // 0x1014 xor eax, eax
    0xc3, // 0x1016 ret
    0x48, 0x89, 0xf0, // 0x1017 mov rax, rsi
    0xc3, // 0x101a ret
];

/// A call to the function itself takes the interface its body settled, so a
/// scratch register written before it is no third argument.
#[test]
fn a_self_call_takes_the_functions_own_interface() {
    let text = rendered(SELF_CALL_WITH_A_SCRATCH_REGISTER, "recurse");
    let call = text
        .lines()
        .find(|line| line.contains("recurse(RDI_0"))
        .unwrap_or_else(|| panic!("no self call: {text}"));
    assert_eq!(call.matches(", ").count(), 1, "{text}");
}

/// `f` calls through memory in a loop with `rsi = b + 1` and `rdi` its own
/// first argument or the last result, then returns 7; `main` calls `f(3, 5)`.
const PARAMETERS_HANDED_TO_AN_UNPROVEN_CALL: &[u8] = &[
    0x53, // 0x1000 push rbx
    0x48, 0x89, 0xf3, // 0x1001 mov rbx, rsi
    0x48, 0x8d, 0x73, 0x01, // 0x1004 lea rsi, [rbx + 1]
    0xff, 0x14, 0x25, 0x00, 0x20, 0x00, 0x00, // 0x1008 call [0x2000]
    0x48, 0x89, 0xc7, // 0x100f mov rdi, rax
    0x48, 0x85, 0xc0, // 0x1012 test rax, rax
    0x75, 0xed, // 0x1015 jne 0x1004
    0xb8, 0x07, 0x00, 0x00, 0x00, // 0x1017 mov eax, 7
    0x5b, // 0x101c pop rbx
    0xc3, // 0x101d ret
    0xbf, 0x03, 0x00, 0x00, 0x00, // 0x101e mov edi, 3
    0xbe, 0x05, 0x00, 0x00, 0x00, // 0x1023 mov esi, 5
    0xe8, 0xd3, 0xff, 0xff, 0xff, // 0x1028 call 0x1000
    0xc3, // 0x102d ret
];

/// A body whose first unclaimed argument slot reaches a call of unproven
/// arity unseen may be passed that argument, so it states no call arity.
#[test]
fn a_parameter_handed_to_an_unproven_call_leaves_the_arity_unproven() {
    let machine = Machine::new("x86-64", "x86-64", 64);
    let target = machine.target();
    let program = Fixture {
        bytes: PARAMETERS_HANDED_TO_AN_UNPROVEN_CALL.to_vec(),
        name: "handed",
    };
    let response = decompile(&target, &program, BASE + 0x1e).expect("decompile");
    let text = response.output.text();
    assert!(!text.contains("handed()"), "{text}");
}

/// `a = x + 1` and `b = y + 1` sit side by side, and `&a` goes to a callee
/// nothing describes.
const NEIGHBOUR_OF_AN_ESCAPED_LOCAL: &[u8] = &[
    0x48, 0x83, 0xec, 0x28, // 0x1000 sub rsp, 40
    0x48, 0xff, 0xc7, // 0x1004 inc rdi
    0x48, 0x89, 0x7c, 0x24, 0x08, // 0x1007 mov [rsp + 8], rdi
    0x48, 0xff, 0xc6, // 0x100c inc rsi
    0x48, 0x89, 0x74, 0x24, 0x10, // 0x100f mov [rsp + 16], rsi
    0x48, 0x8d, 0x7c, 0x24, 0x08, // 0x1014 lea rdi, [rsp + 8]
    0xff, 0x14, 0x25, 0x00, 0x20, 0x00, 0x00, // 0x1019 call [0x2000]
    0x48, 0x8b, 0x44, 0x24, 0x10, // 0x1020 mov rax, [rsp + 16]
    0x48, 0x83, 0xc4, 0x28, // 0x1025 add rsp, 40
    0xc3, // 0x1029 ret
];

/// Every object an escaped address may reach is one object, so the callee's
/// pointer arithmetic from `&a` into `b` is defined C (the extent rule).
#[test]
fn the_objects_an_escaped_address_reaches_are_one() {
    let text = rendered(NEIGHBOUR_OF_AN_ESCAPED_LOCAL, "neighbour");
    let declarations = text
        .lines()
        .filter(|line| {
            let line = line.trim();
            line.starts_with("uint") && line.contains("stack_") && !line.contains('=')
        })
        .collect::<Vec<_>>();
    assert_eq!(declarations.len(), 1, "{text}");
    assert!(declarations[0].contains('['), "{text}");
    assert!(!text.contains("assumed (frame extent"), "{text}");
}

/// `table[x % 3]` on AArch64, with the divisor held in a register:
/// `udiv x10, x0, x9; msub x10, x10, x9, x0`.
const REMAINDER_BY_A_DIVIDE: &[u8] = &[
    0xff, 0x83, 0x00, 0xd1, // sub sp, sp, #32
    0x69, 0x00, 0x80, 0xd2, // mov x9, #3
    0x0a, 0x08, 0xc9, 0x9a, // udiv x10, x0, x9
    0x4a, 0x81, 0x09, 0x9b, // msub x10, x10, x9, x0
    0xe1, 0x03, 0x00, 0xf9, // str x1, [sp]
    0xe2, 0x07, 0x00, 0xf9, // str x2, [sp, #8]
    0xe3, 0x0b, 0x00, 0xf9, // str x3, [sp, #16]
    0xe0, 0x7b, 0x6a, 0xf8, // ldr x0, [sp, x10, lsl #3]
    0xff, 0x83, 0x00, 0x91, // add sp, sp, #32
    0xc0, 0x03, 0x5f, 0xd6, // ret
];

/// A divide by a constant is an exact quotient, so its remainder bounds the
/// index and the table is its three stored rows, none dropped.
#[test]
fn a_remainder_by_a_divide_bounds_a_table_index() {
    let text = rendered_on(
        &Machine::new("aarch64", "aarch64", 64),
        REMAINDER_BY_A_DIVIDE,
        "remainder",
    );
    assert!(text.contains("[3];") || text.contains("[24];"), "{text}");
    assert!(!text.contains("assumed (frame extent"), "{text}");
}
