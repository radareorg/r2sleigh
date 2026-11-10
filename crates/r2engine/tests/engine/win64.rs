//! Microsoft x64 boundary forms (doc/adr-call-boundary.md, S10): the home area the caller
//! allocates is the callee's, so a homing store is no residual and a reload is no stack parameter.

use crate::common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;

/// `f(a, b) { return a + b; }` as MSVC `/Od` builds it, homing both registers, and `caller`
/// calling `f(3, 4)`.
const HOMED: &[u8] = &[
    0x48, 0x89, 0x4c, 0x24, 0x08, // 1000 mov [rsp + 0x8], rcx
    0x48, 0x89, 0x54, 0x24, 0x10, // 1005 mov [rsp + 0x10], rdx
    0x48, 0x83, 0xec, 0x28, // 100a sub rsp, 0x28
    0x48, 0x8b, 0x44, 0x24, 0x30, // 100e mov rax, [rsp + 0x30]
    0x48, 0x03, 0x44, 0x24, 0x38, // 1013 add rax, [rsp + 0x38]
    0x48, 0x83, 0xc4, 0x28, // 1018 add rsp, 0x28
    0xc3, // 101c ret
    0xcc, 0xcc, 0xcc, // 101d padding
    0x48, 0x83, 0xec, 0x28, // 1020 sub rsp, 0x28
    0xb9, 0x03, 0x00, 0x00, 0x00, // 1024 mov ecx, 3
    0xba, 0x04, 0x00, 0x00, 0x00, // 1029 mov edx, 4
    0xe8, 0xcd, 0xff, 0xff, 0xff, // 102e call 0x1000
    0x48, 0x83, 0xc4, 0x28, // 1033 add rsp, 0x28
    0xc3, // 1037 ret
];

/// UCRT's inline `printf` reduced: `print_line(fmt, ...)` homes all four positions and hands
/// `&home[1]` to `__stdio_common_vfprintf` as its `va_list`; `caller` calls `print_line("%d\n", 7)`.
const VA_LIST: &[u8] = &[
    0x48, 0x89, 0x4c, 0x24, 0x08, // 1000 mov [rsp + 0x8], rcx
    0x48, 0x89, 0x54, 0x24, 0x10, // 1005 mov [rsp + 0x10], rdx
    0x4c, 0x89, 0x44, 0x24, 0x18, // 100a mov [rsp + 0x18], r8
    0x4c, 0x89, 0x4c, 0x24, 0x20, // 100f mov [rsp + 0x20], r9
    0x48, 0x83, 0xec, 0x38, // 1014 sub rsp, 0x38
    0x48, 0x8d, 0x44, 0x24, 0x48, // 1018 lea rax, [rsp + 0x48]: &home[1]
    0x48, 0x89, 0x44, 0x24, 0x20, // 101d mov [rsp + 0x20], rax: the fifth argument
    0x45, 0x31, 0xc9, // 1022 xor r9d, r9d: no locale
    0x4c, 0x8b, 0x44, 0x24, 0x40, // 1025 mov r8, [rsp + 0x40]: the format, from home[0]
    0x31, 0xd2, // 102a xor edx, edx
    0x31, 0xc9, // 102c xor ecx, ecx
    0xe8, 0x5d, 0x00, 0x00, 0x00, // 102e call 0x1090
    0x48, 0x83, 0xc4, 0x38, // 1033 add rsp, 0x38
    0xc3, // 1037 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1038 padding
    0x48, 0x83, 0xec, 0x28, // 1040 sub rsp, 0x28
    0x48, 0x8d, 0x0d, 0x55, 0x00, 0x00, 0x00, // 1044 lea rcx, [0x10a0]
    0xba, 0x07, 0x00, 0x00, 0x00, // 104b mov edx, 7
    0xe8, 0xab, 0xff, 0xff, 0xff, // 1050 call 0x1000
    0x48, 0x83, 0xc4, 0x28, // 1055 add rsp, 0x28
    0xc3, // 1059 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 105a padding
    0xff, 0x25, 0x02, 0x00, 0x00, 0x00, // 1090 jmp [rip + 2]: the stub
    0xcc, 0xcc, // 1096 padding
    0, 0, 0, 0, 0, 0, 0, 0, // 1098 the slot
    0, 0, 0, 0, 0, 0, 0, 0, // 10a0 the format
];

/// [`VA_LIST`], its stub `__stdio_common_vfprintf` from UCRT, its format `"%d\n"`.
fn va_list(dll: &str) -> OpenProgram<Literal> {
    let functions = [("print_line", BASE, 0x38), ("caller", BASE + 0x40, 0x1a)];
    let program = Literal::of_code(VA_LIST, &functions)
        .with_data()
        .importing_from(dll, "__stdio_common_vfprintf")
        .pe();
    let mut program = OpenProgram::of(program);
    program.source_mut().write(common::TEXT, b"%d\n\0");
    program
}

/// The home address handed to UCRT's cited `va_list` parameter starts the tail: one fixed
/// parameter, the format the body forwards, and the call counted from its literal (ADR rule 6).
#[test]
fn a_home_handed_on_as_a_cited_va_list_is_a_variadic_tail() {
    let mut open = va_list("api-ms-win-crt-stdio-l1-1-0.dll");
    let callee = rendered(&mut open, BASE);
    assert!(
        callee.contains("print_line(uint64_t arg0, ...)"),
        "{callee}"
    );
    // The format types nothing, so its address spells as the integer the body reads.
    let caller = rendered(&mut open, BASE + 0x40);
    assert!(
        caller.contains("print_line(0x10a0, (uint64_t)7U)"),
        "{caller}"
    );
}

/// `printf("%d %f\n", 7, ...)` through UCRT's `printf`: `xmm2` holds 2.5 and `r8`, its integer
/// duplicate, 0. A variadic callee homes and reads `r8`, so neither register is the operand alone.
const FLOATING: &[u8] = &[
    0x48, 0x83, 0xec, 0x28, // 1000 sub rsp, 0x28
    0x48, 0x8d, 0x0d, 0x95, 0x00, 0x00, 0x00, // 1004 lea rcx, [0x10a0]
    0xba, 0x07, 0x00, 0x00, 0x00, // 100b mov edx, 7
    0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0x04, 0x40, // 1010 mov rax, 2.5
    0x66, 0x48, 0x0f, 0x6e, 0xd0, // 101a movq xmm2, rax
    0x45, 0x31, 0xc0, // 101f xor r8d, r8d
    0xe8, 0x69, 0x00, 0x00, 0x00, // 1022 call 0x1090
    0x48, 0x83, 0xc4, 0x28, // 1027 add rsp, 0x28
    0xc3, // 102b ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, // 102c padding
    0xff, 0x25, 0x02, 0x00, 0x00, 0x00, // 1090 jmp [rip + 2]: the stub
    0xcc, 0xcc, // 1096 padding
    0, 0, 0, 0, 0, 0, 0, 0, // 1098 the slot
    0, 0, 0, 0, 0, 0, 0, 0, // 10a0 the format
];

/// A floating operand at a shared position stays a residual: the callee reads the integer
/// register, the C operand is the float one, and nothing here proves the two equal.
#[test]
fn a_floating_variadic_operand_whose_registers_differ_is_no_argument() {
    let program = Literal::of_code(FLOATING, &[("caller", BASE, 0x2c)])
        .with_data()
        .importing_from("ucrtbase.dll", "printf")
        .pe();
    let mut open = OpenProgram::of(program);
    open.source_mut().write(common::TEXT, b"%d %f\n\0");
    let text = rendered(&mut open, BASE);
    assert!(common::call_arguments(&text, "printf").is_none(), "{text}");
    assert!(text.contains("call to printf"), "{text}");
}

/// The same body calling a DLL no cited table states: the home escapes to no `va_list` the
/// container proves, so no tail is claimed and the call states no count.
#[test]
fn a_home_handed_to_an_uncited_callee_is_no_variadic_tail() {
    let mut open = va_list("unknown.dll");
    let callee = rendered(&mut open, BASE);
    assert!(!callee.contains("..."), "{callee}");
    assert!(callee.contains("only homed"), "{callee}");
    let caller = rendered(&mut open, BASE + 0x40);
    assert!(
        !caller.contains("print_line(0x10a0, (uint64_t)7U)"),
        "{caller}"
    );
}

fn homed() -> OpenProgram<Literal> {
    let functions = [("f", BASE, 0x1d), ("caller", BASE + 0x20, 0x18)];
    OpenProgram::of(Literal::of_code(HOMED, &functions).pe())
}

fn rendered(open: &mut OpenProgram<Literal>, at: u64) -> String {
    open.rendered(at)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// The homing stores are the callee's own: `f` reads its two parameters through them, with no
/// residual, and its caller passes both.
#[test]
fn a_homed_parameter_is_read_through_the_callee_s_home() {
    let mut open = homed();
    let callee = rendered(&mut open, BASE);
    assert!(
        callee.contains("f(uint64_t arg0, uint64_t arg1)"),
        "{callee}"
    );
    assert!(!callee.contains("r2sleigh_residual"), "{callee}");
    let caller = rendered(&mut open, BASE + 0x20);
    assert!(caller.contains("f(3, 4)"), "{caller}");
}
