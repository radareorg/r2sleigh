//! A call hands its callee exactly the arguments the callee's body states it takes, or shows what
//! it cannot prove (ROADMAP P7, audit W7): never the registers the caller happened to write.

use crate::common;

use common::{BASE, GLIBC, Literal};
use r2engine::program::{Libc, OpenProgram, PlatformEvidence};
use r2ssa::body_boundary::SlotUse;
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

/// `caller`: `call [rip + 0x1a]; mov eax, 7; ret`, the slot at 0x1020 the loader binds to an import.
const CALL_THROUGH_A_SLOT_THEN_RETURN_SEVEN: &[u8] = &[
    0xff, 0x15, 0x1a, 0x00, 0x00, 0x00, // 1000 call [rip + 0x1a]
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1006 mov eax, 7
    0xc3, // 100b ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 100c padding
    0, 0, 0, 0, 0, 0, 0, 0, // 1020 the slot
];

/// A noreturn import ends the path only where the loader's binding stays: a slot the program may
/// rebind is an opaque call that comes back, so the code after it is walked and rendered.
#[test]
fn a_call_through_a_writable_noreturn_slot_comes_back_and_a_sealed_one_does_not() {
    let render = |sealed: bool| {
        let slot = BASE + 0x20;
        let mut literal = Literal::of_code(
            CALL_THROUGH_A_SLOT_THEN_RETURN_SEVEN,
            &[("caller", BASE, 0xc)],
        )
        .running_on(&[PlatformEvidence::Interpreter(Libc::Glibc)])
        .writable_data_after(slot)
        .loader_written(common::import_write(slot, 8, "_Exit"))
        .relocated(common::import_slot(slot, "_Exit"));
        if sealed {
            literal = literal.sealed(slot..slot + 8);
        }
        OpenProgram::of(literal)
            .rendered(BASE)
            .expect("it renders")
            .response
            .output
            .into_text()
    };
    let writable = render(false);
    assert!(writable.contains('7'), "{writable}");
    let sealed = render(true);
    assert!(sealed.contains("_Exit("), "{sealed}");
    assert!(!sealed.contains('7'), "{sealed}");
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

/// `mov eax, [rip + 0xa]; ret`, the word at 0x1010 holding 0x11223344 in the file.
const LOAD_A_WORD: &[u8] = &[
    0x8b, 0x05, 0x0a, 0x00, 0x00, 0x00, // 1000 mov eax, [rip + 0xa]
    0xc3, // 1006 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1007 padding
    0x44, 0x33, 0x22, 0x11, // 1010 the word
];

/// A RELRO word no record writes is the file's value when the interpreter relocates and seals the
/// image before its code runs; with no interpreter, start-up may write it first (ROADMAP M18, P5).
#[test]
fn a_load_of_a_sealed_word_folds_only_where_an_interpreter_seals_the_image() {
    let word = BASE + 0x10;
    let render = |interpreted: bool| {
        let mut literal = Literal::of_code(LOAD_A_WORD, &[("load", BASE, 0x7)])
            .writable_data_after(word)
            .sealed(word..word + 4);
        if interpreted {
            literal = literal.interpreted();
        }
        let rendered = OpenProgram::of(literal).rendered(BASE);
        rendered.expect("it renders").response.output.into_text()
    };
    assert!(render(true).contains("0x11223344"), "{}", render(true));
    assert!(!render(false).contains("0x11223344"), "{}", render(false));
}

/// A send to `objc_msgSend`, variadic as objc4 declares it, states no argument count: the call is
/// a gap naming the import and why, never an unsupported instruction (audit M3, RF's W10 case).
#[test]
fn a_variadic_call_with_no_count_is_a_gap_naming_its_callee() {
    let darwin = Literal::of_code(CALL_THROUGH_A_SLOT, &[("caller", BASE, 0x11)])
        .mach_o()
        .with_dylib("objc_msgSend", "/usr/lib/libobjc.A.dylib");
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

/// glibc declares `__libc_start_main` with seven arguments: `place` puts the seventh in the
/// first stack slot, so a caller that stores none leaves that argument a gap naming it (D163).
#[test]
fn an_import_s_seventh_argument_is_placed_on_the_stack() {
    let text = plt_caller("__libc_start_main");
    assert!(
        text.contains("call to __libc_start_main: no value reaches its declared argument 6 */"),
        "{text}"
    );
}

/// After `.plt`: six register arguments, the seventh stored at `[rsp]`, then the call.
const SEVENTH_ON_THE_STACK: [u8; 0x56] = common::plt_then(&[
    0x48, 0x83, 0xec, 0x08, // 1020 sub rsp, 8
    0x48, 0xc7, 0x04, 0x24, 0x77, 0x00, 0x00, 0x00, // 1024 mov qword [rsp], 0x77
    0xbf, 0x01, 0x00, 0x00, 0x00, // 102c mov edi, 1
    0xbe, 0x02, 0x00, 0x00, 0x00, // 1031 mov esi, 2
    0xba, 0x03, 0x00, 0x00, 0x00, // 1036 mov edx, 3
    0xb9, 0x04, 0x00, 0x00, 0x00, // 103b mov ecx, 4
    0x41, 0xb8, 0x05, 0x00, 0x00, 0x00, // 1040 mov r8d, 5
    0x41, 0xb9, 0x06, 0x00, 0x00, 0x00, // 1046 mov r9d, 6
    0xe8, 0xbf, 0xff, 0xff, 0xff, // 104c call stub
    0x48, 0x83, 0xc4, 0x08, // 1051 add rsp, 8
    0xc3, // 1055 ret
]);

/// The declared seventh argument sits at entry + 8, past the return address the call pushes,
/// so the call reads the caller's `[rsp]` (D163, PR 352 review).
#[test]
fn a_declared_stack_argument_is_the_callers_outgoing_slot() {
    let literal = Literal::plt_wrapped("__libc_start_main", &SEVENTH_ON_THE_STACK);
    let text = OpenProgram::of(literal)
        .rendered(common::PLT_CALLER)
        .expect("it renders")
        .response
        .output
        .into_text();
    let arguments = common::call_arguments(&text, "__libc_start_main").unwrap_or_default();
    assert_eq!(arguments.len(), 7, "{text}");
    assert!(arguments[6].ends_with("119U"), "{text}");
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

/// `mov eax, esi; ret`, and a caller that hands it `5` in `esi`.
const HOLE: &[u8] = &[
    0x89, 0xf0, 0xc3, // 1000 mov eax, esi; ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // padding
    0x6b, 0xff, 0x07, // 1010 imul edi, edi, 7
    0xbe, 0x05, 0x00, 0x00, 0x00, // 1013 mov esi, 5
    0xe8, 0xe3, 0xff, 0xff, 0xff, // 1018 call 0x1000
    0xc3, // 101d ret
];

/// An unread `rdi` below a read `rsi` is a hole: two parameters, the first spelled as the slot's
/// typedef, and no floor (W12; the prefix rule made `rsi` a floor and dropped it).
#[test]
fn an_unread_slot_below_a_read_one_is_a_hole_spelled_as_its_typedef() {
    let functions = [("f", BASE, 3), ("caller", BASE + 0x10, 0x0e)];
    let mut open = OpenProgram::of(Literal::of_code(HOLE, &functions));
    let prepared = open.prepared(BASE).expect("it prepares");
    let shared = prepared.artifact().shared_artifact();
    let interface = (shared.machine_context().function_interface()).expect("an interface");
    assert_eq!(interface.arity_floor(), None);
    let bases = (interface.parameters().iter())
        .map(|parameter| parameter.basis())
        .collect::<Vec<_>>();
    assert_eq!(
        bases,
        [
            Some(r2source::Basis::Convention),
            Some(r2source::Basis::Decoded)
        ]
    );
    // The evidence travels with the sealed artifact.
    let boundary = (shared.facts().body_boundary.as_ref()).expect("a recovered body states it");
    let uses = boundary.slots.iter().map(|(_, used)| used).take(2);
    assert!(matches!(
        uses.collect::<Vec<_>>()[..],
        [SlotUse::Unread, SlotUse::Read { .. }]
    ));
    let text = (open.rendered(BASE).expect("it renders").response.output).into_text();
    let header = (text.lines())
        .find(|line| line.contains("f("))
        .unwrap_or_default();
    assert!(
        header.contains("(r2sleigh_unread_u64 arg0, uint32_t arg1)"),
        "{text}"
    );
}

/// The caller passes the hole its typed residual: the `edi` it computed reaches no parameter, so
/// no value of it is shown (doc/adr-call-boundary.md, Refusals).
#[test]
fn a_caller_passes_a_hole_its_typed_residual_and_no_value() {
    let functions = [("f", BASE, 3), ("caller", BASE + 0x10, 0x0e)];
    let text = surveyed(HOLE, &functions, BASE + 0x10);
    assert!(text.contains("f((r2sleigh_unread_u64)0, 5)"), "{text}");
    assert!(!text.contains("* 7"), "{text}");
}

/// `mov eax, [rsp + 8]; ret`: the first argument-area slot is read, and no register slot is.
#[test]
fn an_argument_area_read_past_the_prefix_is_a_floor_of_that_cause() {
    const CODE: &[u8] = &[0x8b, 0x44, 0x24, 0x08, 0xc3];
    let cause = floor_cause(Literal::of_code(CODE, &[("f", BASE, 5)]));
    assert_eq!(cause, [SourceFloorCause::ArgumentAreaRead]);
}

/// `mov eax, [rsp + 0x40000000]; ret`: one load names slot 0x7fffffff of the argument area.
#[test]
fn a_read_far_up_the_argument_area_is_a_floor_past_the_hole_budget() {
    const CODE: &[u8] = &[0x8b, 0x84, 0x24, 0x00, 0x00, 0x00, 0x40, 0xc3];
    let cause = floor_cause(Literal::of_code(CODE, &[("f", BASE, 8)]));
    assert_eq!(
        cause,
        [
            SourceFloorCause::ArgumentAreaRead,
            SourceFloorCause::ArgumentAreaPastBudget
        ]
    );
}

/// The six integer registers summed, then `add rax, [rsp + 0x210]`: slot 65 of the argument area
/// is read behind a full section, so the 64 holes below it stand and the list is a floor.
#[test]
fn holes_past_the_budget_stop_the_stack_parameters_as_a_floor() {
    const CODE: &[u8] = &[
        0x48, 0x89, 0xf8, // mov rax, rdi
        0x48, 0x01, 0xf0, // add rax, rsi
        0x48, 0x01, 0xd0, // add rax, rdx
        0x48, 0x01, 0xc8, // add rax, rcx
        0x4c, 0x01, 0xc0, // add rax, r8
        0x4c, 0x01, 0xc8, // add rax, r9
        0x48, 0x03, 0x84, 0x24, 0x10, 0x02, 0x00, 0x00, // add rax, [rsp + 0x210]
        0xc3, // ret
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0xcc,
    ];
    let mut open = OpenProgram::of(Literal::of_code(CODE, &[("f", BASE, 0x1b)]));
    let prepared = open.prepared(BASE).expect("it prepares");
    let shared = prepared.artifact().shared_artifact();
    let interface = (shared.machine_context().function_interface()).expect("an interface");
    let floor = interface.arity_floor().expect("its arity is a floor");
    assert_eq!(floor.causes(), [SourceFloorCause::ArgumentAreaPastBudget]);
    assert_eq!(interface.parameters().len(), 6 + 64);
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

/// `f`: `call g; ret`; `g`: `mov eax, [rsp + 8]; ret`, a floor of its own (D37's
/// `ArgumentAreaRead`).
#[test]
fn a_call_to_a_callee_that_is_a_floor_is_a_floor_handed_to_it() {
    const CODE: &[u8] = &[
        0xe8, 0x0b, 0x00, 0x00, 0x00, 0xc3, // 1000 call 0x1010; ret
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1006 padding
        0x8b, 0x44, 0x24, 0x08, 0xc3, // 1010 mov eax, [rsp + 8]; ret
    ];
    let functions = [("f", BASE, 6), ("g", BASE + 0x10, 5)];
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

/// bash's `sh_unset_nodelay_mode` after `.plt`: the body moves `edi`, and two `fcntl` calls read `fd`.
const DECLARED_INT_MOVED: [u8; 0x42] = common::plt_then(&[
    0x53, // 1020 push rbx
    0x31, 0xd2, // 1021 xor edx, edx
    0x31, 0xc0, // 1023 xor eax, eax
    0x89, 0xfb, // 1025 mov ebx, edi
    0xbe, 0x03, 0x00, 0x00, 0x00, // 1027 mov esi, 3
    0xe8, 0xdf, 0xff, 0xff, 0xff, // 102c call stub
    0x89, 0xdf, // 1031 mov edi, ebx
    0xbe, 0x04, 0x00, 0x00, 0x00, // 1033 mov esi, 4
    0x89, 0xc2, // 1038 mov edx, eax
    0x31, 0xc0, // 103a xor eax, eax
    0x5b, // 103c pop rbx
    0xe9, 0xce, 0xff, 0xff, 0xff, // 103d jmp stub
]);

/// `return fcntl(fd, F_GETFL) & 4;` after `.plt`: `fd` is handed on untouched.
const DECLARED_INT: [u8; 0x38] = common::plt_then(&[
    0x48, 0x83, 0xec, 0x08, // 1020 sub rsp, 8
    0xbe, 0x03, 0x00, 0x00, 0x00, // 1024 mov esi, 3
    0x31, 0xc0, // 1029 xor eax, eax
    0xe8, 0xe0, 0xff, 0xff, 0xff, // 102b call stub
    0x48, 0x83, 0xc4, 0x08, // 1030 add rsp, 8
    0x83, 0xe0, 0x04, // 1034 and eax, 4
    0xc3, // 1037 ret
]);

/// The caller of `fcntl` at `code`'s one parameter type.
fn fcntl_caller_parameters(code: &'static [u8]) -> (String, Vec<(String, String)>) {
    let text = OpenProgram::of(Literal::plt_wrapped("fcntl", code))
        .rendered(common::PLT_CALLER)
        .expect("it renders")
        .response
        .output
        .into_text();
    let header = (text.lines())
        .find(|line| line.contains("fcn_1020(") && !line.ends_with(';'))
        .unwrap_or_default();
    let parameters = common::parameters(header);
    (text, parameters)
}

/// A declared integer is read at its own width, never the register's: the call's argument is
/// the `edi` lane the body read, so `int fd` is a 32-bit parameter (ROADMAP D105).
#[test]
fn a_declared_integer_is_read_at_its_width_not_the_registers() {
    let (text, parameters) = fcntl_caller_parameters(&DECLARED_INT_MOVED);
    assert_eq!(parameters.len(), 1, "{text}");
    assert_eq!(parameters[0].0, "uint32_t", "{text}");
}

/// A declared integer handed on untouched is the lane its callee holds (ROADMAP D105).
#[test]
fn a_declared_integer_handed_on_is_a_parameter_at_its_width() {
    let (text, parameters) = fcntl_caller_parameters(&DECLARED_INT);
    assert_eq!(parameters.len(), 1, "{text}");
    assert_eq!(parameters[0].0, "uint32_t", "{text}");
}

/// `int p_fcntl2(int fd, int flags) { return fcntl(fd, F_SETFL, flags); }` at clang -O0, after
/// `.plt`: `flags` reaches only `fcntl`'s uncounted tail.
const UNCOUNTED_TAIL: [u8; 0x46] = common::plt_then(&[
    0x55, // 1020 push rbp
    0x48, 0x89, 0xe5, // 1021 mov rbp, rsp
    0x48, 0x83, 0xec, 0x10, // 1024 sub rsp, 0x10
    0x89, 0x7d, 0xfc, // 1028 mov [rbp - 4], edi
    0x89, 0x75, 0xf8, // 102b mov [rbp - 8], esi
    0x8b, 0x7d, 0xfc, // 102e mov edi, [rbp - 4]
    0x8b, 0x55, 0xf8, // 1031 mov edx, [rbp - 8]
    0xbe, 0x04, 0x00, 0x00, 0x00, // 1034 mov esi, 4
    0xb0, 0x00, // 1039 mov al, 0
    0xe8, 0xd0, 0xff, 0xff, 0xff, // 103b call stub
    0x48, 0x83, 0xc4, 0x10, // 1040 add rsp, 0x10
    0x5d, // 1044 pop rbp
    0xc3, // 1045 ret
]);

/// A header whose parameters are only a floor says so on its proof line (ROADMAP D100): the
/// proven prefix is not the whole interface.
#[test]
fn a_floor_of_parameters_is_named_on_the_proof_line() {
    let (text, parameters) = fcntl_caller_parameters(&UNCOUNTED_TAIL);
    let proof = (text.lines())
        .find(|line| line.contains("r2dec proof"))
        .unwrap_or_default();
    assert!(
        proof.contains(&format!(
            "the parameters are a floor: at least {}",
            parameters.len()
        )),
        "{text}"
    );
}

/// gcc -O0 `int zero_of(int x) { return 0; }`: `x` is homed and never loaded. `caller` is
/// `mov edi, 5; call zero_of; ret`.
const HOMED_ONLY: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, // 1000 endbr64
    0x55, // 1004 push rbp
    0x48, 0x89, 0xe5, // 1005 mov rbp, rsp
    0x89, 0x7d, 0xfc, // 1008 mov [rbp - 4], edi
    0xb8, 0x00, 0x00, 0x00, 0x00, // 100b mov eax, 0
    0x5d, // 1010 pop rbp
    0xc3, // 1011 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1012
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1020 mov edi, 5
    0xe8, 0xd6, 0xff, 0xff, 0xff, // 1025 call 0x1000
    0xc3, // 102a ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 102b padding
];

/// A floor whose only cause is a home nothing loads reads no slot past the parameters: the call
/// passes exactly them, and the register it wrote reaches nothing (D165).
#[test]
fn a_call_past_a_homed_only_floor_passes_exactly_the_parameters() {
    let functions = [("zero_of", BASE, 0x12), ("caller", BASE + 0x20, 0x0b)];
    let callee = floor_cause(Literal::of_code(HOMED_ONLY, &functions));
    assert_eq!(callee, [SourceFloorCause::Homed]);
    let text = surveyed(HOMED_ONLY, &functions, BASE + 0x20);
    assert!(text.contains("zero_of()"), "{text}");
    assert!(!text.contains("a floor), and this call writes"), "{text}");
}

/// `caller`: `mov rsi, rdi; mov edi, 5; call f; ret`, at `BASE + 0x20` behind an `f` of `N` bytes.
const fn before_its_caller<const N: usize>(f: [u8; N]) -> [u8; 0x2e] {
    const CALLER: [u8; 14] = [
        0x48, 0x89, 0xfe, // 1020 mov rsi, rdi
        0xbf, 0x05, 0x00, 0x00, 0x00, // 1023 mov edi, 5
        0xe8, 0xd3, 0xff, 0xff, 0xff, // 1028 call 0x1000
        0xc3, // 102d ret
    ];
    let mut bytes = [0xcc; 0x2e];
    let mut at = 0;
    while at < N {
        bytes[at] = f[at];
        at += 1;
    }
    at = 0;
    while at < CALLER.len() {
        bytes[0x20 + at] = CALLER[at];
        at += 1;
    }
    bytes
}

/// clang -O1 `table_walk`'s tail: `sete dl` stores the flag `je` branches on, so on the taken edge
/// DL is 1 and `cmove eax, ecx` keeps EAX; ECX is read only where `mov ecx, [rsi]` wrote it.
const DEAD_SELECT_ARM: [u8; 0x2e] = before_its_caller([
    0x48, 0x85, 0xff, // 1000 test rdi, rdi
    0x0f, 0x94, 0xc2, // 1003 sete dl
    0x74, 0x02, // 1006 je 0x100a
    0x8b, 0x0e, // 1008 mov ecx, [rsi]
    0x89, 0xf8, // 100a mov eax, edi
    0xf6, 0xc2, 0x01, // 100c test dl, 1
    0x0f, 0x44, 0xc1, // 100f cmove eax, ecx
    0xc3, // 1012 ret
]);

/// The same, with DL loaded from memory: nothing ties it to the edge, so the entry ECX is read.
const LIVE_SELECT_ARM: [u8; 0x2e] = before_its_caller([
    0x48, 0x85, 0xff, // 1000 test rdi, rdi
    0x8a, 0x56, 0x04, // 1003 mov dl, [rsi + 4]
    0x74, 0x02, // 1006 je 0x100a
    0x8b, 0x0e, // 1008 mov ecx, [rsi]
    0x89, 0xf8, // 100a mov eax, edi
    0xf6, 0xc2, 0x01, // 100c test dl, 1
    0x0f, 0x44, 0xc1, // 100f cmove eax, ecx
    0xc3, // 1012 ret
]);

/// R8B is 1 on the path that leaves ECX as it arrived and 0 on the one that loads it, and only
/// `r8b == 0` reaches `mov eax, ecx`: the merge's arrival arm is never read there.
const DEAD_BRANCH_ARM: [u8; 0x2e] = before_its_caller([
    0x48, 0x85, 0xff, // 1000 test rdi, rdi
    0x75, 0x08, // 1003 jne 0x100d
    0x41, 0xb8, 0x01, 0x00, 0x00, 0x00, // 1005 mov r8d, 1
    0xeb, 0x05, // 100b jmp 0x1012
    0x8b, 0x0e, // 100d mov ecx, [rsi]
    0x45, 0x31, 0xc0, // 100f xor r8d, r8d
    0x45, 0x84, 0xc0, // 1012 test r8b, r8b
    0x74, 0x03, // 1015 je 0x101a
    0x31, 0xc0, // 1017 xor eax, eax
    0xc3, // 1019 ret
    0x89, 0xc8, // 101a mov eax, ecx
    0xc3, // 101c ret
]);

/// The same, with R8D loaded from memory on the arrival path: the entry ECX may reach the read.
const LIVE_BRANCH_ARM: [u8; 0x2e] = before_its_caller([
    0x48, 0x85, 0xff, // 1000 test rdi, rdi
    0x75, 0x08, // 1003 jne 0x100d
    0x44, 0x8b, 0x46, 0x04, // 1005 mov r8d, [rsi + 4]
    0x66, 0x90, // 1009 nop
    0xeb, 0x05, // 100b jmp 0x1012
    0x8b, 0x0e, // 100d mov ecx, [rsi]
    0x45, 0x31, 0xc0, // 100f xor r8d, r8d
    0x45, 0x84, 0xc0, // 1012 test r8b, r8b
    0x74, 0x03, // 1015 je 0x101a
    0x31, 0xc0, // 1017 xor eax, eax
    0xc3, // 1019 ret
    0x89, 0xc8, // 101a mov eax, ecx
    0xc3, // 101c ret
]);

/// `f` and its caller under `aa`, for a body of `size` bytes.
fn f_and_its_caller(code: &'static [u8], size: u64) -> (String, String) {
    let functions = [("f", BASE, size), ("caller", BASE + 0x20, 0x0e)];
    (
        surveyed(code, &functions, BASE),
        surveyed(code, &functions, BASE + 0x20),
    )
}

/// How many parameters `f`'s header states, past any type the rendering declares first.
fn parameter_count(f: &str) -> usize {
    let header = f.lines().find(|line| line.contains(" f(")).expect(f);
    common::parameters(header).len()
}

/// A merge arm no path reads is no read of the entry register: two parameters, and the caller
/// passes two arguments with no residual (ROADMAP D214).
fn assert_two_parameters((f, caller): (String, String)) {
    assert_eq!(parameter_count(&f), 2, "{f}");
    assert!(!f.contains("r2sleigh_residual"), "{f}");
    let arguments = common::call_arguments(&caller, "f").expect(&caller);
    assert_eq!(arguments.len(), 2, "{caller}");
    assert!(!caller.contains("r2sleigh_residual"), "{caller}");
}

#[test]
fn a_select_arm_dead_under_the_edge_that_carries_it_reads_no_parameter() {
    assert_two_parameters(f_and_its_caller(&DEAD_SELECT_ARM, 0x13));
}

#[test]
fn a_select_arm_whose_condition_no_edge_decides_is_read() {
    let (f, _) = f_and_its_caller(&LIVE_SELECT_ARM, 0x13);
    assert_eq!(parameter_count(&f), 4, "{f}");
}

#[test]
fn a_merge_arm_its_block_never_leaves_to_the_read_under_reads_no_parameter() {
    assert_two_parameters(f_and_its_caller(&DEAD_BRANCH_ARM, 0x1d));
}

#[test]
fn a_merge_arm_whose_flag_no_edge_decides_is_read() {
    let (f, _) = f_and_its_caller(&LIVE_BRANCH_ARM, 0x1d);
    assert_eq!(parameter_count(&f), 4, "{f}");
}
