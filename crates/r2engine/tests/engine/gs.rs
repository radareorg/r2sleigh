//! Microsoft `/GS` (doc/adr-call-boundary.md, "S17 as built"): the load configuration's cookie,
//! a check proven from its body, and the non-returning facts its failure rests on.

use crate::common;

use common::{BASE, Literal, TEXT};
use r2engine::program::OpenProgram;

/// `check(x)`: `cmp rcx, [cookie]; jne fail; ret; fail: call ExitProcess`, and `guarded`, which
/// saves `[cookie] ^ rsp`, sets `eax = 7` and hands the saved word `^ rsp` to `check`.
const GUARDED: &[u8] = &[
    0x48, 0x3b, 0x0d, 0x99, 0x00, 0x00, 0x00, // 1000 cmp rcx, [rip + 0x99]: the cookie
    0x75, 0x01, // 1007 jne 0x100a
    0xc3, // 1009 ret
    0xe8, 0x81, 0x00, 0x00, 0x00, // 100a call 0x1090: ExitProcess
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 100f padding
    0x48, 0x83, 0xec, 0x28, // 1020 sub rsp, 0x28
    0x48, 0x8b, 0x05, 0x75, 0x00, 0x00, 0x00, // 1024 mov rax, [rip + 0x75]: the cookie
    0x48, 0x31, 0xe0, // 102b xor rax, rsp
    0x48, 0x89, 0x44, 0x24, 0x20, // 102e mov [rsp + 0x20], rax
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1033 mov eax, 7
    0x48, 0x8b, 0x4c, 0x24, 0x20, // 1038 mov rcx, [rsp + 0x20]
    0x48, 0x31, 0xe1, // 103d xor rcx, rsp
    0xe8, 0xbb, 0xff, 0xff, 0xff, // 1040 call 0x1000
    0x48, 0x83, 0xc4, 0x28, // 1045 add rsp, 0x28
    0xc3, // 1049 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 104a padding
    0xff, 0x25, 0x02, 0x00, 0x00, 0x00, // 1090 jmp [rip + 2]: the stub
    0xcc, 0xcc, // 1096 padding
    0, 0, 0, 0, 0, 0, 0, 0, // 1098 the slot
    0x32, 0xa2, 0xdf, 0x2d, 0x99, 0x2b, 0, 0, // 10a0 the cookie
];

/// [`GUARDED`] with the failing arm `xor eax, eax; ret`: it comes back, so nothing is proven.
const RETURNING: &[u8] = &{
    let mut code = [0u8; 0xa8];
    let mut at = 0;
    while at < code.len() {
        code[at] = GUARDED[at];
        at += 1;
    }
    // 100a xor eax, eax; ret
    code[0x0a] = 0x31;
    code[0x0b] = 0xc0;
    code[0x0c] = 0xc3;
    code[0x0d] = 0xcc;
    code[0x0e] = 0xcc;
    code
};

/// [`GUARDED`] whose check also fails on a second argument: `if (x != cookie || y != 0) exit`.
/// Whether it returns turns on `rdx`, which no cookie decides.
const SECOND_TEST: &[u8] = &{
    let mut code = [0u8; 0xa8];
    let mut at = 0;
    while at < code.len() {
        code[at] = GUARDED[at];
        at += 1;
    }
    let tail = [
        0x75, 0x06, // 1007 jne 0x100f
        0x48, 0x85, 0xd2, // 1009 test rdx, rdx
        0x75, 0x01, // 100c jne 0x100f
        0xc3, // 100e ret
        0xe8, 0x7c, 0x00, 0x00, 0x00, // 100f call 0x1090: ExitProcess
    ];
    let mut at = 0;
    while at < tail.len() {
        code[0x07 + at] = tail[at];
        at += 1;
    }
    code
};

/// [`GUARDED`] as MSVC's i386 `/GS` builds it: `check` takes the word in `ecx` (`__fastcall`), and
/// `guarded` saves `[cookie] ^ ebp` below its frame pointer.
const GUARDED_I386: &[u8] = &{
    let head: [u8; 0x43] = [
        0x3b, 0x0d, 0xa0, 0x10, 0x00, 0x00, // 1000 cmp ecx, [0x10a0]: the cookie
        0x75, 0x01, // 1006 jne 0x1009
        0xc3, // 1008 ret
        0xe8, 0x82, 0x00, 0x00, 0x00, // 1009 call 0x1090: ExitProcess
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0xcc, 0xcc, 0xcc, // 100e padding
        0x55, // 1020 push ebp
        0x8b, 0xec, // 1021 mov ebp, esp
        0x83, 0xec, 0x04, // 1023 sub esp, 4
        0xa1, 0xa0, 0x10, 0x00, 0x00, // 1026 mov eax, [0x10a0]: the cookie
        0x33, 0xc5, // 102b xor eax, ebp
        0x89, 0x45, 0xfc, // 102d mov [ebp - 4], eax
        0xb8, 0x07, 0x00, 0x00, 0x00, // 1030 mov eax, 7
        0x8b, 0x4d, 0xfc, // 1035 mov ecx, [ebp - 4]
        0x33, 0xcd, // 1038 xor ecx, ebp
        0xe8, 0xc1, 0xff, 0xff, 0xff, // 103a call 0x1000
        0x8b, 0xe5, // 103f mov esp, ebp
        0x5d, // 1041 pop ebp
        0xc3, // 1042 ret
    ];
    let mut code = [0xccu8; 0xa8];
    let mut at = 0;
    while at < head.len() {
        code[at] = head[at];
        at += 1;
    }
    // 1090 jmp [0x1098]: the stub; 1098 the slot; 10a0 the cookie.
    let tail = [
        0xff, 0x25, 0x98, 0x10, 0x00, 0x00, 0xcc, 0xcc, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut at = 0;
    while at < tail.len() {
        code[0x90 + at] = tail[at];
        at += 1;
    }
    let cookie = [0x32, 0xa2, 0xdf, 0x2d, 0, 0, 0, 0];
    let mut at = 0;
    while at < cookie.len() {
        code[0xa0 + at] = cookie[at];
        at += 1;
    }
    code
};

const CHECK: u64 = BASE;
const CALLER: u64 = BASE + 0x20;

fn program(code: &'static [u8], check: &str, cookie: Option<u64>) -> OpenProgram<Literal> {
    let functions = [(check, CHECK, 0x0f), ("guarded", CALLER, 0x2a)];
    let mut program = Literal::of_code(code, &functions)
        .with_data()
        .writable_data_after(TEXT)
        .importing_from("KERNEL32.dll", "ExitProcess")
        .pe();
    if let Some(cookie) = cookie {
        program = program.with_security_cookie(cookie);
    }
    OpenProgram::of(program)
}

fn rendered(open: &mut OpenProgram<Literal>, at: u64) -> String {
    open.rendered(at)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// The save, the reload and the call to the proven check are the compiler's, elided under the
/// UB-free premise. The 7 the caller returns past the check stays a residual (D231).
#[test]
fn a_call_to_a_proven_check_of_the_load_config_cookie_is_elided() {
    let mut open = program(GUARDED, "check", Some(TEXT));
    let text = rendered(&mut open, CALLER);
    assert!(!text.contains("check("), "{text}");
    assert!(!text.contains("0x10a0"), "{text}");
    assert!(text.contains("compiler-inserted"), "{text}");
}

/// D230: i386's check takes the saved `[cookie] ^ ebp` in `ecx`, which the UCRT row cites; the
/// save, reload and call are compiler-inserted under the UB-free premise, as on x86-64 (no x86
/// 32-bit C renders, so the prepared body is the gate). Without the cookie nothing is.
#[test]
fn an_i386_check_of_the_cookie_in_ecx_is_compiler_inserted() {
    let inserted = |cookie: Option<u64>| {
        let functions = [("check", CHECK, 0x0e), ("guarded", CALLER, 0x23)];
        let mut program = Literal::of_code(GUARDED_I386, &functions)
            .in_i386()
            .with_data()
            .writable_data_after(TEXT)
            .importing_from("KERNEL32.dll", "ExitProcess")
            .pe();
        if let Some(cookie) = cookie {
            program = program.with_security_cookie(cookie);
        }
        let mut open = OpenProgram::of(program);
        let prepared = open.prepared(CALLER).expect("it prepares");
        let shared = prepared.artifact().shared_artifact();
        let function = shared.function();
        let premised = function
            .premises()
            .contains(&r2source::Premise::UbFreeSource);
        (function.compiler_inserted().iter().count(), premised)
    };
    let (ops, premised) = inserted(Some(TEXT));
    assert!(ops > 0 && premised, "{ops} {premised}");
    assert_eq!(inserted(None), (0, false));
}

/// No load configuration states a cookie, so the same bytes are no check.
#[test]
fn without_a_load_config_cookie_the_check_is_a_call() {
    let mut open = program(GUARDED, "check", None);
    let text = rendered(&mut open, CALLER);
    assert!(text.contains("check("), "{text}");
    assert!(text.contains("0x10a0"), "{text}");
}

/// A body whose failing arm comes back proves nothing, whatever its name says.
#[test]
fn a_cookie_compare_that_comes_back_is_no_check_whatever_its_name() {
    let mut open = program(RETURNING, "__security_check_cookie", Some(TEXT));
    let text = rendered(&mut open, CALLER);
    assert!(text.contains("__security_check_cookie("), "{text}");
    assert!(text.contains("0x10a0"), "{text}");
}

/// `TerminateProcess(GetCurrentProcess(), code)` as a tail jump: Microsoft states it never returns
/// for the calling process, so `raise` never comes back and its caller's `return 5` is unreached.
const TERMINATES: &[u8] = &[
    0x48, 0x83, 0xec, 0x28, // 1000 sub rsp, 0x28
    0xff, 0x15, 0x8e, 0x00, 0x00, 0x00, // 1004 call [rip + 0x8e]: GetCurrentProcess
    0x48, 0x89, 0xc1, // 100a mov rcx, rax
    0xba, 0x09, 0x04, 0x00, 0xc0, // 100d mov edx, 0xc0000409
    0x48, 0x83, 0xc4, 0x28, // 1012 add rsp, 0x28
    0xff, 0x25, 0x8c, 0x00, 0x00, 0x00, // 1016 jmp [rip + 0x8c]: TerminateProcess
    0xcc, 0xcc, 0xcc, 0xcc, // 101c padding
    0x48, 0x83, 0xec, 0x28, // 1020 sub rsp, 0x28
    0xe8, 0xd7, 0xff, 0xff, 0xff, // 1024 call 0x1000
    0xb8, 0x05, 0x00, 0x00, 0x00, // 1029 mov eax, 5
    0x48, 0x83, 0xc4, 0x28, // 102e add rsp, 0x28
    0xc3, // 1032 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1033 padding
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1090 GetCurrentProcess's stub room
    0, 0, 0, 0, 0, 0, 0, 0, // 1098 its slot
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 10a0 TerminateProcess's stub room
    0, 0, 0, 0, 0, 0, 0, 0, // 10a8 its slot
];

/// [`TERMINATES`] handing `rbx` in place of the handle: no row says that call ends the process.
const TERMINATES_ANOTHER: &[u8] = &{
    let mut code = [0u8; 0xb0];
    let mut at = 0;
    while at < code.len() {
        code[at] = TERMINATES[at];
        at += 1;
    }
    code[0x0c] = 0xd9; // 100a mov rcx, rbx
    code
};

fn terminating(code: &'static [u8]) -> OpenProgram<Literal> {
    terminating_from(
        code,
        &[("raise", BASE, 0x1c), ("caller", BASE + 0x20, 0x13)],
    )
}

fn terminating_from(code: &'static [u8], functions: &[(&str, u64, u64)]) -> OpenProgram<Literal> {
    let symbol = |name: &str, vaddr| r2engine::program::Symbol {
        name: name.into(),
        vaddr,
        import: true,
        library: Some("KERNEL32.dll".into()),
        ..r2engine::program::Symbol::default()
    };
    let program = Literal::of_code(code, functions)
        .importing_through(0x1090..0x1096, 0x1098, "GetCurrentProcess")
        .importing_through(0x10a0..0x10a6, 0x10a8, "TerminateProcess")
        .declaring(symbol("GetCurrentProcess", 0x1098))
        .declaring(symbol("TerminateProcess", 0x10a8))
        .pe();
    OpenProgram::of(program)
}

/// [`TERMINATES`] where `raise` calls `TerminateProcess` and would return after it (D229).
const TERMINATES_BY_CALL: &[u8] = &[
    0x48, 0x83, 0xec, 0x28, // 1000 sub rsp, 0x28
    0xff, 0x15, 0x8e, 0x00, 0x00, 0x00, // 1004 call [rip + 0x8e]: GetCurrentProcess
    0x48, 0x89, 0xc1, // 100a mov rcx, rax
    0xba, 0x09, 0x04, 0x00, 0xc0, // 100d mov edx, 0xc0000409
    0xff, 0x15, 0x90, 0x00, 0x00, 0x00, // 1012 call [rip + 0x90]: TerminateProcess
    0x48, 0x83, 0xc4, 0x28, // 1018 add rsp, 0x28
    0xc3, 0xcc, 0xcc, 0xcc, // 101c ret; padding
    0x48, 0x83, 0xec, 0x28, // 1020 sub rsp, 0x28
    0xe8, 0xd7, 0xff, 0xff, 0xff, // 1024 call 0x1000
    0xb8, 0x05, 0x00, 0x00, 0x00, // 1029 mov eax, 5
    0x48, 0x83, 0xc4, 0x28, // 102e add rsp, 0x28
    0xc3, // 1032 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1033 padding
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1090 GetCurrentProcess's stub room
    0, 0, 0, 0, 0, 0, 0, 0, // 1098 its slot
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 10a0 TerminateProcess's stub room
    0, 0, 0, 0, 0, 0, 0, 0, // 10a8 its slot
];

#[test]
fn calling_terminate_on_the_current_process_does_not_return() {
    let mut open = terminating(TERMINATES_BY_CALL);
    let text = rendered(&mut open, BASE + 0x20);
    assert!(text.contains("__attribute__((noreturn))"), "{text}");
    assert!(!text.contains("(5)"), "{text}");
}

#[test]
fn terminating_the_current_process_does_not_return() {
    let mut open = terminating(TERMINATES);
    let text = rendered(&mut open, BASE + 0x20);
    assert!(text.contains("__attribute__((noreturn))"), "{text}");
    assert!(!text.contains("(5)"), "{text}");
}

#[test]
fn terminating_another_handle_may_return() {
    let mut open = terminating(TERMINATES_ANOTHER);
    let text = rendered(&mut open, BASE + 0x20);
    assert!(!text.contains("noreturn"), "{text}");
    assert!(text.contains("return r2sleigh_carrier_u32(5)"), "{text}");
}

/// [`TERMINATES`] with a branch past the handle's copy: on that path `rcx` is the caller's, so the
/// tail jump may return and `raise` comes back.
const BRANCHED_INTO: &[u8] = &[
    0x48, 0x83, 0xec, 0x28, // 1000 sub rsp, 0x28
    0x85, 0xc9, // 1004 test ecx, ecx
    0x75, 0x0a, // 1006 jne 0x1012
    0xff, 0x15, 0x8a, 0x00, 0x00, 0x00, // 1008 call [rip + 0x8a]: GetCurrentProcess
    0x48, 0x89, 0xc1, // 100e mov rcx, rax
    0x90, // 1011 nop
    0xba, 0x09, 0x04, 0x00, 0xc0, // 1012 mov edx, 0xc0000409
    0x48, 0x83, 0xc4, 0x28, // 1017 add rsp, 0x28
    0xff, 0x25, 0x87, 0x00, 0x00, 0x00, // 101b jmp [rip + 0x87]: TerminateProcess
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1021 padding
    0x48, 0x83, 0xec, 0x28, // 1030 sub rsp, 0x28
    0xe8, 0xc7, 0xff, 0xff, 0xff, // 1034 call 0x1000
    0xb8, 0x05, 0x00, 0x00, 0x00, // 1039 mov eax, 5
    0x48, 0x83, 0xc4, 0x28, // 103e add rsp, 0x28
    0xc3, // 1042 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1043 padding
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1090 GetCurrentProcess's stub room
    0, 0, 0, 0, 0, 0, 0, 0, // 1098 its slot
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 10a0 TerminateProcess's stub room
    0, 0, 0, 0, 0, 0, 0, 0, // 10a8 its slot
];

/// A branch into the run between the handle and the jump reaches the jump with another `rcx`.
#[test]
fn a_branch_past_the_handle_s_copy_may_return() {
    let functions = [("raise", BASE, 0x21), ("caller", BASE + 0x30, 0x13)];
    let mut open = terminating_from(BRANCHED_INTO, &functions);
    let text = rendered(&mut open, BASE + 0x30);
    assert!(!text.contains("noreturn"), "{text}");
    assert!(text.contains("return r2sleigh_carrier_u32(5)"), "{text}");
}

/// A check that also tests another argument may end the process with the cookie intact: no check.
#[test]
fn a_cookie_compare_that_also_tests_another_argument_is_no_check() {
    let mut open = program(SECOND_TEST, "check", Some(TEXT));
    let text = rendered(&mut open, CALLER);
    assert!(text.contains("check("), "{text}");
}

/// [`GUARDED`] with `mov al, [rdx]; movzx eax, al` in place of `mov eax, 7`: the low byte replaces
/// the save's in RAX, and only that byte is read (testapp `0x140006138`'s `movsx rax, al`, D230).
const LANE_OVER_THE_SAVE: &[u8] = &{
    let mut code = [0u8; 0xa8];
    let mut at = 0;
    while at < code.len() {
        code[at] = GUARDED[at];
        at += 1;
    }
    let lane = [0x8a, 0x02, 0x0f, 0xb6, 0xc0];
    let mut at = 0;
    while at < lane.len() {
        code[0x33 + at] = lane[at];
        at += 1;
    }
    code
};

/// The save's other seven bytes stay in RAX unread until the extension writes it whole, so the
/// check is elided; the `<< 32`-free byte is the result.
#[test]
fn a_save_whose_unread_upper_bytes_stay_in_a_register_is_elided() {
    let mut open = program(LANE_OVER_THE_SAVE, "check", Some(TEXT));
    let text = rendered(&mut open, CALLER);
    assert!(!text.contains("check("), "{text}");
    assert!(!text.contains("0x10a0"), "{text}");
    assert!(text.contains("compiler-inserted"), "{text}");
    assert!(
        text.contains("return r2sleigh_carrier_u32((uint32_t)(uint8_t)tmp_1033_0_1);"),
        "{text}"
    );
}
