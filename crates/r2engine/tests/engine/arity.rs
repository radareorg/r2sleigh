//! A call hands its callee exactly the arguments the callee's body states it takes, or shows what
//! it cannot prove (ROADMAP P7, audit W7): never the registers the caller happened to write.

use crate::common;

use common::{BASE, GLIBC, Literal};
use r2engine::program::OpenProgram;
use r2ssa::{SourceFloorCause, SourceUnprovenCall};

/// `f` writes both result registers and reads no argument (`xor eax, eax; pxor xmm0, xmm0`): its
/// result is unproven and its arity exact. `caller` sets `edi` and `esi` for nothing, then calls it.
const EXACT_WITH_AN_UNPROVEN_RESULT: &[u8] = &[
    0x31, 0xc0, // 1000 xor eax, eax
    0x66, 0x0f, 0xef, 0xc0, // 1002 pxor xmm0, xmm0
    0xc3, // 1006 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1007 padding
    0x53, // 1010 push rbx
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1011 mov edi, 5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1016 mov esi, 7
    0xe8, 0xe0, 0xff, 0xff, 0xff, // 101b call 0x1000
    0x5b, // 1020 pop rbx
    0x31, 0xc0, // 1021 xor eax, eax
    0xc3, // 1023 ret
];

/// `crc32_init(0x402060, 61)` was the registers gcc set for a later call: a callee whose arity is
/// exact keeps it when its result is unproven, so the call passes none (audit W7).
#[test]
fn an_exact_callee_with_an_unproven_result_is_called_with_exactly_its_arguments() {
    let text = OpenProgram::of(Literal::of_code(
        EXACT_WITH_AN_UNPROVEN_RESULT,
        &[("f", BASE, 0x07), ("caller", BASE + 0x10, 0x14)],
    ))
    .rendered(BASE + 0x10)
    .expect("it renders")
    .response
    .output
    .into_text();
    assert!(text.contains("f();"), "{text}");
    assert!(!text.contains("f(5"), "{text}");
}

/// `f`: `call g; add eax, 1; ret`, handing on the `rdi` it arrived with; `g`: `mov eax, [rdi]; ret`;
/// `caller`: `mov edi, 5; mov esi, 7; call f; ret`, `esi` set for nothing.
const HANDED_ON_ONE: &[u8] = &[
    0xe8, 0x0b, 0x00, 0x00, 0x00, // 1000 call 0x1010
    0x83, 0xc0, 0x01, // 1005 add eax, 1
    0xc3, // 1008 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1009 padding
    0x8b, 0x07, // 1010 mov eax, [rdi]
    0xc3, // 1012 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1013 padding
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1020 mov edi, 5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1025 mov esi, 7
    0xe8, 0xd1, 0xff, 0xff, 0xff, // 102a call 0x1000
    0xc3, // 102f ret
];

/// Resolved alone, `f`'s call to `g` may be handed any slot, so `f` takes at least none; under `aa`
/// `f` is resolved again against `g`, which takes exactly one, so `f` does too: `f(5)`, not the
/// `f(5, 7)` the caller's registers said (audit W7, `shape_bool_caller`).
#[test]
fn under_aa_a_floor_its_callee_owns_is_resolved_bottom_up() {
    let mut open = OpenProgram::of(Literal::of_code(
        HANDED_ON_ONE,
        &[
            ("f", BASE, 0x09),
            ("g", BASE + 0x10, 0x03),
            ("caller", BASE + 0x20, 0x10),
        ],
    ));
    open.analyse_program().expect("it surveys");
    let text = open
        .rendered(BASE + 0x20)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(
        text.contains("f(5)") || text.contains("f((uint64_t)5U)"),
        "{text}"
    );
    assert!(!text.contains(", 7)"), "{text}");
}

/// Without `aa`, `f`'s arity is a floor of none and `caller` writes two slots: the call is a gap
/// that names `f` and its floor, never `f(5, 7)` and never an unsupported instruction (audit M3).
#[test]
fn a_call_past_a_floor_is_a_gap_naming_its_callee_and_floor() {
    let text = OpenProgram::of(Literal::of_code(
        HANDED_ON_ONE,
        &[
            ("f", BASE, 0x09),
            ("g", BASE + 0x10, 0x03),
            ("caller", BASE + 0x20, 0x10),
        ],
    ))
    .rendered(BASE + 0x20)
    .expect("it renders")
    .response
    .output
    .into_text();
    assert!(
        text.contains(
            "(render::values): call to f: its arity is only at least 0 (a floor), and this call writes 2 */"
        ),
        "{text}"
    );
    assert!(!text.contains("UnsupportedInstruction"), "{text}");
    assert!(!text.contains("f(5"), "{text}");
}

/// `HANDED_ON_ONE` with `tail`: `mov edi, 5; mov esi, 7; jmp f` in place of `caller`.
const TAIL_PAST_A_FLOOR: &[u8] = &[
    0xe8, 0x0b, 0x00, 0x00, 0x00, // 1000 call 0x1010
    0x83, 0xc0, 0x01, // 1005 add eax, 1
    0xc3, // 1008 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 1009 padding
    0x8b, 0x07, // 1010 mov eax, [rdi]
    0xc3, // 1012 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1013 padding
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1020 mov edi, 5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1025 mov esi, 7
    0xe9, 0xd1, 0xff, 0xff, 0xff, // 102a jmp 0x1000
];

/// A tail jump past `f`'s floor leaves a gap naming `f` (audit M3), not a bare
/// `TailTransferNotRendered`.
#[test]
fn a_tail_jump_past_a_floor_is_a_gap_naming_its_callee() {
    let text = OpenProgram::of(Literal::of_code(
        TAIL_PAST_A_FLOOR,
        &[
            ("f", BASE, 0x09),
            ("g", BASE + 0x10, 0x03),
            ("tail", BASE + 0x20, 0x0f),
        ],
    ))
    .rendered(BASE + 0x20)
    .expect("it renders")
    .response
    .output
    .into_text();
    assert!(
        text.contains("TailTransferNotRendered at 0x1020 (render::control): call to f:"),
        "{text}"
    );
}

/// `caller`: `mov edi, 5; mov esi, 7; call [rip + 0x10]; ret`, the slot at 0x1020 the loader binds
/// to `puts`, in a segment the program may write.
const CALL_THROUGH_A_SLOT: &[u8] = &[
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1000 mov edi, 5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1005 mov esi, 7
    0xff, 0x15, 0x10, 0x00, 0x00, 0x00, // 100a call [rip + 0x10]
    0xc3, // 1010 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1011 padding
    0, 0, 0, 0, 0, 0, 0, 0, // 1020 the slot
];

/// `caller` over the slot bound to `import`, sealed after load or not.
fn slot_caller(import: &str, sealed: bool) -> String {
    slot_caller_in(
        Literal::of_code(CALL_THROUGH_A_SLOT, &[("caller", BASE, 0x11)]),
        import,
        sealed,
    )
}

fn slot_caller_in(literal: Literal, import: &str, sealed: bool) -> String {
    let slot = BASE + 0x20;
    let mut literal = literal
        .writable_data_after(slot)
        .loader_written(common::import_write(slot, 8, import))
        .relocated(common::import_slot(slot, import));
    if sealed {
        literal = literal.sealed(slot..slot + 8);
    }
    OpenProgram::of(literal)
        .rendered(BASE)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// A call through a slot the loader binds to an import and seals is a call to that import, with
/// its declaration's arity: `puts(5)`, not a pointer call handed every register written (audit
/// W8). A slot the program may rebind stays a call through memory.
#[test]
fn a_call_through_a_sealed_import_slot_calls_the_import() {
    let text = slot_caller("puts", true);
    assert!(text.contains("puts((const char*)(uint64_t)5U)"), "{text}");
    assert!(!text.contains(", 7)"), "{text}");
    let text = slot_caller("puts", false);
    assert!(!text.contains("puts("), "{text}");
}

/// ld.so's `call [__rtld_malloc]`: a sealed slot no relocation fills holds 0 in the file, and
/// start-up code may write it before the seal, so the call goes through memory, never to `fcn_0`.
#[test]
fn a_call_through_a_sealed_slot_the_loader_leaves_is_a_call_through_memory() {
    let slot = BASE + 0x20;
    let literal = Literal::of_code(CALL_THROUGH_A_SLOT, &[("caller", BASE, 0x11)])
        .writable_data_after(slot)
        .sealed(slot..slot + 8);
    let text = OpenProgram::of(literal)
        .rendered(BASE)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(!text.contains("fcn_0"), "{text}");
    assert!(text.contains("call to an indirect target"), "{text}");
}

/// A send to `objc_msgSend`, variadic as objc4 declares it, states no argument count: the call is
/// a gap naming the import and why, never an unsupported instruction (audit M3, RF's W10 case).
#[test]
fn a_variadic_call_with_no_count_is_a_gap_naming_its_callee() {
    let darwin = Literal::of_code(CALL_THROUGH_A_SLOT, &[("caller", BASE, 0x11)]).mach_o();
    let text = slot_caller_in(darwin, "objc_msgSend", true);
    assert!(
        text.contains(
            "call to objc_msgSend: variadic, its argument count unproven (missing_format_parameter) */"
        ),
        "{text}"
    );
    assert!(!text.contains("UnsupportedInstruction"), "{text}");
}

/// `caller` writes `edi` and calls the `.plt` stub bound to `import`, in a program the container
/// says runs on glibc.
fn plt_caller(import: &str) -> String {
    let glibc = r2engine::program::PlatformEvidence::Interpreter(r2engine::program::Libc::Glibc);
    OpenProgram::of(Literal::plt_passing(import).running_on(&[glibc]))
        .rendered(common::PLT_CALLER)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// An import's arity is its declaration's, never its stub's: `_Znwm` is operator new as the C++
/// runtime declares it, so the call renders with its one argument (P7, C++ runtime).
#[test]
fn an_import_takes_its_arity_from_its_declaration() {
    let text = plt_caller("_Znwm");
    assert!(text.contains("_Znwm(16"), "{text}");
    assert!(!text.contains("a floor"), "{text}");
}

/// An import no declaration states is a gap that says so, never a floor of 0 read off the
/// `jmp [slot]` its stub is (P7, C++ runtime).
#[test]
fn an_undeclared_import_is_a_gap_naming_its_missing_declaration() {
    let text = plt_caller("_ZN3Foo3barEv");
    assert!(
        text.contains(
            "call to _ZN3Foo3barEv: the import has no declaration to state its arguments */"
        ),
        "{text}"
    );
    assert!(!text.contains("_ZN3Foo3barEv(16"), "{text}");
}

/// glibc declares `__libc_start_main` with seven arguments, and x86-64 passes six in registers:
/// a declaration this convention does not place states nothing, and the gap says so.
#[test]
fn an_import_whose_declaration_is_not_placed_is_a_gap_saying_so() {
    let text = plt_caller("__libc_start_main");
    assert!(
        text.contains(
            "call to __libc_start_main: the import's declaration has an argument this convention \
             does not place */"
        ),
        "{text}"
    );
}

/// `f`: `test edi, edi; je ret; sub edi, 1; call f; ret`, a self-recursive function that never
/// writes `rsi`; `caller`: `mov edi, 5; mov esi, 7; call f; ret`.
const SELF_RECURSIVE: &[u8] = &[
    0x85, 0xff, // 1000 test edi, edi
    0x74, 0x08, // 1002 je 0x100c
    0x83, 0xef, 0x01, // 1004 sub edi, 1
    0xe8, 0xf4, 0xff, 0xff, 0xff, // 1007 call 0x1000
    0xc3, // 100c ret
    0xcc, 0xcc, 0xcc, // 100d padding
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1010 mov edi, 5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1015 mov esi, 7
    0xe8, 0xe1, 0xff, 0xff, 0xff, // 101a call 0x1000
    0xc3, // 101f ret
];

/// `root` rendered once `aa` surveyed the program.
fn surveyed(code: &'static [u8], functions: &[(&str, u64, u64)], root: u64) -> String {
    let mut open = OpenProgram::of(Literal::of_code(code, functions));
    open.analyse_program().expect("it surveys");
    open.rendered(root)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// Alone, `f`'s call to itself may be handed `rsi`, so its arity is a floor of one; the slot is
/// read only at a finite depth, so the least fixpoint is exact: `f(5)`, never `f(5, 7)`.
#[test]
fn under_aa_a_self_recursive_floor_is_its_least_fixpoint() {
    let functions = [("f", BASE, 0x0d), ("caller", BASE + 0x10, 0x10)];
    let text = surveyed(SELF_RECURSIVE, &functions, BASE + 0x10);
    assert!(
        text.contains("f(5") || text.contains("f((uint32_t)5"),
        "{text}"
    );
    assert!(!text.contains(", 7)"), "{text}");
    assert!(!text.contains("a floor"), "{text}");
}

/// gcc -O1's review.c `fact`: `mov eax, 1` before `cmp edi, 1`, so its call to itself is handed
/// `al` as well as `edi`.
const FACT_O1: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, // 1000 endbr64
    0xb8, 0x01, 0x00, 0x00, 0x00, // 1004 mov eax, 1
    0x83, 0xff, 0x01, // 1009 cmp edi, 1
    0x7f, 0x01, // 100c jg 0x100f
    0xc3, // 100e ret
    0x53, // 100f push rbx
    0x89, 0xfb, // 1010 mov ebx, edi
    0x8d, 0x7f, 0xff, // 1012 lea edi, [rdi - 1]
    0xe8, 0xe6, 0xff, 0xff, 0xff, // 1015 call 0x1000
    0x0f, 0xaf, 0xc3, // 101a imul eax, ebx
    0x5b, // 101d pop rbx
    0xc3, // 101e ret
];

/// Under `aa` the root reads itself resolved, as its callers do: its recursive call takes the one
/// argument `fact`'s least fixpoint states, never the `al` count W14 refuses on a floor.
#[test]
fn under_aa_a_recursive_root_calls_itself_with_its_resolved_arity() {
    let mut open =
        OpenProgram::of(Literal::of_code(FACT_O1, &[("fact", BASE, 0x1f)]).running_on(GLIBC));
    open.analyse_program().expect("it surveys");
    let text = open
        .rendered(BASE)
        .expect("it renders")
        .response
        .output
        .into_text();
    assert!(text.contains("= fact("), "{text}");
    assert!(!text.contains("vector count"), "{text}");
}

/// `a`: `test edi, edi; je ret; sub edi, 1; call b; ret`, handing `b` the `rsi` it never wrote;
/// `b`: `test esi, esi; je ret; sub edi, 1; call a; ret`; `caller` writes `edi`, `esi` and `edx`.
const MUTUAL_RISE: &[u8] = &[
    0x85, 0xff, // 1000 test edi, edi
    0x74, 0x08, // 1002 je 0x100c
    0x83, 0xef, 0x01, // 1004 sub edi, 1
    0xe8, 0x04, 0x00, 0x00, 0x00, // 1007 call 0x1010
    0xc3, // 100c ret
    0xcc, 0xcc, 0xcc, // 100d padding
    0x85, 0xf6, // 1010 test esi, esi
    0x74, 0x08, // 1012 je 0x101c
    0x83, 0xef, 0x01, // 1014 sub edi, 1
    0xe8, 0xe4, 0xff, 0xff, 0xff, // 1017 call 0x1000
    0xc3, // 101c ret
    0xcc, 0xcc, 0xcc, // 101d padding
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1020 mov edi, 5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1025 mov esi, 7
    0xba, 0x09, 0x00, 0x00, 0x00, // 102a mov edx, 9
    0xe8, 0xcc, 0xff, 0xff, 0xff, // 102f call 0x1000
    0xc3, // 1034 ret
];

/// Alone `a` reads one slot and `b` two, each a floor the other owns. Seeded exact there, `a` hands
/// `b` its `rsi` and rises to two, so `b` is resolved again: `a(5, 7)`, never `a(5)` nor `, 9)`.
#[test]
fn under_aa_a_two_member_cycle_rises_to_its_least_fixpoint() {
    let functions = [
        ("a", BASE, 0x0d),
        ("b", BASE + 0x10, 0x0d),
        ("caller", BASE + 0x20, 0x15),
    ];
    let text = surveyed(MUTUAL_RISE, &functions, BASE + 0x20);
    assert!(text.contains("a(5, 7)"), "{text}");
    assert!(!text.contains(", 9)"), "{text}");
    assert!(!text.contains("a floor"), "{text}");
}

/// `p` calls `q` and `q` calls `r`, each handing on the `rsi` it never wrote; `r` reads `esi` and
/// calls `p`; `caller` writes `edi`, `esi` and `edx` and calls `p`.
const RISE_THROUGH_A_CHAIN: &[u8] = &[
    0x85, 0xff, // 1000 test edi, edi
    0x74, 0x08, // 1002 je 0x100c
    0x83, 0xef, 0x01, // 1004 sub edi, 1
    0xe8, 0x04, 0x00, 0x00, 0x00, // 1007 call 0x1010
    0xc3, // 100c ret
    0xcc, 0xcc, 0xcc, // 100d padding
    0x85, 0xff, // 1010 test edi, edi
    0x74, 0x08, // 1012 je 0x101c
    0x83, 0xef, 0x01, // 1014 sub edi, 1
    0xe8, 0x04, 0x00, 0x00, 0x00, // 1017 call 0x1020
    0xc3, // 101c ret
    0xcc, 0xcc, 0xcc, // 101d padding
    0x85, 0xf6, // 1020 test esi, esi
    0x74, 0x08, // 1022 je 0x102c
    0x83, 0xef, 0x01, // 1024 sub edi, 1
    0xe8, 0xd4, 0xff, 0xff, 0xff, // 1027 call 0x1000
    0xc3, // 102c ret
    0xcc, 0xcc, 0xcc, // 102d padding
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1030 mov edi, 5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1035 mov esi, 7
    0xba, 0x09, 0x00, 0x00, 0x00, // 103a mov edx, 9
    0xe8, 0xbc, 0xff, 0xff, 0xff, // 103f call 0x1000
    0xc3, // 1044 ret
];

/// Resolved first against `q`'s seed of one, `p` stays at one; `q` then rises to two against `r`,
/// so `p`, which calls it, is resolved again and rises too: `p(5, 7)`, never `p(5)`.
#[test]
fn under_aa_a_rise_resolves_again_the_members_that_call_it() {
    let functions = [
        ("p", BASE, 0x0d),
        ("q", BASE + 0x10, 0x0d),
        ("r", BASE + 0x20, 0x0d),
        ("caller", BASE + 0x30, 0x15),
    ];
    let text = surveyed(RISE_THROUGH_A_CHAIN, &functions, BASE + 0x30);
    assert!(text.contains("p(5, 7)"), "{text}");
    assert!(!text.contains(", 9)"), "{text}");
    assert!(!text.contains("a floor"), "{text}");
}

/// `f`: `call [rdi]; call g; ret`, its result `g`'s; `g`: `test edi, edi; je ret; call f; ret`;
/// `caller`: `mov edi, 5; mov esi, 7; call g; ret`.
const CYCLE_THROUGH_AN_INDIRECT_CALL: &[u8] = &[
    0xff, 0x17, // 1000 call [rdi]
    0xe8, 0x09, 0x00, 0x00, 0x00, // 1002 call 0x1010
    0xc3, // 1007 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1008 padding
    0x85, 0xff, // 1010 test edi, edi
    0x74, 0x05, // 1012 je 0x1019
    0xe8, 0xe7, 0xff, 0xff, 0xff, // 1014 call 0x1000
    0xc3, // 1019 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 101a padding
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1020 mov edi, 5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1025 mov esi, 7
    0xe8, 0xe1, 0xff, 0xff, 0xff, // 102a call 0x1010
    0xc3, // 102f ret
];

/// `f`'s indirect call may be handed any slot, a floor no member owns, so `g`, which hands `f` its
/// `rdi`, stays a floor through it: the call is a gap, never `g(5)` nor `g(5, 7)`.
#[test]
fn under_aa_a_cycle_through_an_indirect_call_stays_a_floor() {
    let functions = [
        ("f", BASE, 0x08),
        ("g", BASE + 0x10, 0x0a),
        ("caller", BASE + 0x20, 0x10),
    ];
    let text = surveyed(CYCLE_THROUGH_AN_INDIRECT_CALL, &functions, BASE + 0x20);
    assert!(
        text.contains("call to g: its arity is only at least 1 (a floor), and this call writes 2"),
        "{text}"
    );
    assert!(!text.contains("g(5"), "{text}");
}

/// Why the function at `BASE` is only a floor of arity, as recovery states it (ROADMAP D37).
fn floor_cause(literal: Literal) -> Vec<SourceFloorCause> {
    let mut open = OpenProgram::of(literal);
    let prepared = open.prepared(BASE).expect("it prepares");
    let shared = prepared.artifact().shared_artifact();
    let interface = (shared.machine_context().function_interface()).expect("an interface");
    let floor = interface.arity_floor().expect("its arity is a floor");
    floor.causes().to_vec()
}

/// The bytes of `code` at `BASE`, padded to the slot at `BASE + 0x20` the programs below read.
const fn with_a_slot<const N: usize>(code: [u8; N]) -> [u8; 0x30] {
    let mut bytes = [0xcc; 0x30];
    let mut at = 0;
    while at < N {
        bytes[at] = code[at];
        at += 1;
    }
    bytes
}

/// `mov eax, 39; syscall; ret`: the kernel reads registers no operation names.
#[test]
fn a_supervisor_entry_is_a_floor_of_that_cause() {
    const CODE: &[u8] = &[0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3];
    let cause = floor_cause(Literal::of_code(CODE, &[("f", BASE, 8)]));
    assert_eq!(cause, [SourceFloorCause::SupervisorEntry]);
}

/// `mov rax, rdi; jmp rax`: a jump through a register the walk cannot follow.
#[test]
fn an_unfollowed_transfer_is_a_floor_of_that_cause() {
    const CODE: &[u8] = &[0x48, 0x89, 0xf8, 0xff, 0xe0];
    let cause = floor_cause(Literal::of_code(CODE, &[("f", BASE, 5)]));
    assert_eq!(cause, [SourceFloorCause::UnresolvedTransfer]);
}

/// `mov eax, esi; ret`: `rsi` is read and `rdi` is not, so the prefix stops short of it.
#[test]
fn a_register_read_past_the_prefix_is_a_floor_of_that_cause() {
    const CODE: &[u8] = &[0x89, 0xf0, 0xc3];
    let cause = floor_cause(Literal::of_code(CODE, &[("f", BASE, 3)]));
    assert_eq!(cause, [SourceFloorCause::RegisterRead]);
}

/// `mov eax, [rsp + 8]; ret`: the first argument-area slot is read, and no register slot is.
#[test]
fn an_argument_area_read_past_the_prefix_is_a_floor_of_that_cause() {
    const CODE: &[u8] = &[0x8b, 0x44, 0x24, 0x08, 0xc3];
    let cause = floor_cause(Literal::of_code(CODE, &[("f", BASE, 5)]));
    assert_eq!(cause, [SourceFloorCause::ArgumentAreaRead]);
}

/// All six argument registers stored, then `ud2`: no exit places the argument area.
#[test]
fn an_argument_area_no_exit_places_is_a_floor_of_that_cause() {
    const CODE: &[u8] = &[
        0x48, 0x89, 0x37, // mov [rdi], rsi
        0x48, 0x89, 0x0a, // mov [rdx], rcx
        0x4d, 0x89, 0x08, // mov [r8], r9
        0x0f, 0x0b, // ud2
    ];
    let cause = floor_cause(Literal::of_code(CODE, &[("f", BASE, 11)]));
    assert_eq!(cause, [SourceFloorCause::ArgumentAreaUnplaced]);
}

/// A floor whose one cause is a call of unproven arity handed the `rdi` the function was entered with.
fn handed_to(call: SourceUnprovenCall) -> Vec<SourceFloorCause> {
    vec![SourceFloorCause::HandedOn(call)]
}

/// `call [rip + 0x1a]; ret`, the slot at 0x1020 in memory the program may write.
#[test]
fn a_call_through_memory_is_a_floor_handed_to_no_callee() {
    const CODE: [u8; 0x30] = with_a_slot([0xff, 0x15, 0x1a, 0, 0, 0, 0xc3]);
    let literal = Literal::of_code(&CODE, &[("f", BASE, 7)]).writable_data_after(BASE + 0x20);
    let cause = floor_cause(literal);
    assert_eq!(cause, handed_to(SourceUnprovenCall::Indirect));
}

/// `call 0x1000; ret`: the callee is the function itself, which states no arity yet.
#[test]
fn a_call_to_a_callee_nothing_states_is_a_floor_handed_to_it() {
    const CODE: &[u8] = &[0xe8, 0xfb, 0xff, 0xff, 0xff, 0xc3];
    let cause = floor_cause(Literal::of_code(CODE, &[("f", BASE, 6)]));
    assert_eq!(cause, handed_to(SourceUnprovenCall::Unstated(BASE)));
}

/// `f`: `call g; ret`; `g`: `mov eax, esi; ret`, a floor of its own.
#[test]
fn a_call_to_a_callee_that_is_a_floor_is_a_floor_handed_to_it() {
    const CODE: &[u8] = &[
        0xe8, 0x0b, 0x00, 0x00, 0x00, 0xc3, // 1000 call 0x1010; ret
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1006 padding
        0x89, 0xf0, 0xc3, // 1010 mov eax, esi; ret
    ];
    let functions = [("f", BASE, 6), ("g", BASE + 0x10, 3)];
    let cause = floor_cause(Literal::of_code(CODE, &functions));
    assert_eq!(cause, handed_to(SourceUnprovenCall::Floor(BASE + 0x10)));
}

/// `f`: `call g; ret`, writing no stack argument; `g` stores its six register arguments and reads
/// the seventh, `[rsp + 8]`, so it states seven arguments and the call reaches only six.
#[test]
fn a_call_whose_stated_argument_is_unreached_is_a_floor_handed_to_it() {
    const CODE: &[u8] = &[
        0xe8, 0x1b, 0x00, 0x00, 0x00, 0xc3, // 1000 call 0x1020; ret
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1006 padding
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1010 padding
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 101a padding
        0x48, 0x89, 0x37, // 1020 mov [rdi], rsi
        0x48, 0x89, 0x0a, // 1023 mov [rdx], rcx
        0x4d, 0x89, 0x08, // 1026 mov [r8], r9
        0x8b, 0x44, 0x24, 0x08, // 1029 mov eax, [rsp + 8]
        0xc3, // 102d ret
    ];
    let functions = [("f", BASE, 6), ("g", BASE + 0x20, 14)];
    let cause = floor_cause(Literal::of_code(CODE, &functions));
    assert_eq!(cause, handed_to(SourceUnprovenCall::Stated(BASE + 0x20)));
}
