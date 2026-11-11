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
    // `&home[1]` is the callee's fifth argument: the homes stay in memory, and home 0 keeps its store.
    assert!(callee.contains("(uint64_t)arg0);"), "{callee}");
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

/// [`FLOATING`] with `r8` written from `xmm2` by `movq r8, xmm2`: both registers hold one
/// value, so the operand is the double the float register carries (ADR "S17 as built").
fn floating_from_one_value() -> Vec<u8> {
    let mut code = FLOATING[..0x1f].to_vec();
    code.extend([0x66, 0x49, 0x0f, 0x7e, 0xd0]); // 101f movq r8, xmm2
    code.extend([0xe8, 0x67, 0x00, 0x00, 0x00]); // 1024 call 0x1090
    code.extend([0x48, 0x83, 0xc4, 0x28, 0xc3]); // 1029 add rsp, 0x28; ret
    code.resize(0x90, 0xcc);
    code.extend(&FLOATING[0x90..]);
    code
}

/// A floating operand at a shared position is an argument where SSA proves its integer
/// duplicate equal to it: the call passes the double.
#[test]
fn a_floating_variadic_operand_both_registers_carry_is_the_double() {
    let code: &'static [u8] = Box::leak(floating_from_one_value().into_boxed_slice());
    let program = Literal::of_code(code, &[("caller", BASE, 0x2e)])
        .with_data()
        .importing_from("ucrtbase.dll", "printf")
        .pe();
    let mut open = OpenProgram::of(program);
    open.source_mut().write(common::TEXT, b"%d %f\n\0");
    let text = rendered(&mut open, BASE);
    let arguments = common::call_arguments(&text, "printf").unwrap_or_else(|| panic!("{text}"));
    assert_eq!(arguments.len(), 3, "{text}");
    // The operand is `xmm2`'s low lane read as a double: 2.5's bits, which `rax` was loaded with.
    assert!(
        arguments[2].starts_with("r2sleigh_float_from_bits_64("),
        "{text}"
    );
    assert!(text.contains("0x4004000000000000"), "{text}");
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

/// `store_through` writes 9 through its fifth argument; `caller` passes `&local` there, on the
/// stack at `[rsp + 0x20]`, from `r11`, which no convention passes, and reads `local` back.
const FIFTH: &[u8] = &[
    0x48, 0x8b, 0x44, 0x24, 0x28, // 1000 mov rax, [rsp + 0x28]: the fifth argument
    0xc7, 0x00, 0x09, 0x00, 0x00, 0x00, // 1005 mov dword [rax], 9
    0xc3, // 100b ret
    0xcc, 0xcc, 0xcc, 0xcc, // 100c padding
    0x48, 0x83, 0xec, 0x38, // 1010 sub rsp, 0x38
    0xc7, 0x44, 0x24, 0x30, 0x05, 0x00, 0x00, 0x00, // 1014 mov dword [rsp + 0x30], 5
    0x4c, 0x8d, 0x5c, 0x24, 0x30, // 101c lea r11, [rsp + 0x30]
    0x4c, 0x89, 0x5c, 0x24, 0x20, // 1021 mov [rsp + 0x20], r11
    0x31, 0xc9, // 1026 xor ecx, ecx
    0x31, 0xd2, // 1028 xor edx, edx
    0x45, 0x31, 0xc0, // 102a xor r8d, r8d
    0x45, 0x31, 0xc9, // 102d xor r9d, r9d
    0xe8, 0xcb, 0xff, 0xff, 0xff, // 1030 call 0x1000
    0x8b, 0x44, 0x24, 0x30, // 1035 mov eax, [rsp + 0x30]
    0x48, 0x83, 0xc4, 0x38, // 1039 add rsp, 0x38
    0xc3, // 103d ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

/// A local whose address is the fifth argument stays in memory: the callee reads the outgoing slot
/// that holds it, so its store stands before the call and its read after (D217).
#[test]
fn a_local_passed_as_the_fifth_argument_stays_in_memory() {
    let functions = [("store_through", BASE, 0xc), ("caller", BASE + 0x10, 0x2e)];
    let mut open = OpenProgram::of(Literal::of_code(FIFTH, &functions).pe());
    let caller = rendered(&mut open, BASE + 0x10);
    common::assert_local_stays_in_memory(&caller);
}

/// clang -O0 `int sum(int n, ...)` for `x86_64-pc-windows-msvc`: it homes `rdx`, `r8` and `r9`,
/// keeps `va_list ap = &home[1]` in a frame cell and adds `*(int *)ap` `n` times, stepping `ap`
/// by `step`; `caller` calls `sum(3, 1, 2, 3)`.
fn summing(step: u8) -> &'static [u8] {
    let mut code = vec![
        0x48, 0x83, 0xec, 0x18, // 1000 sub rsp, 0x18
        0x4c, 0x89, 0x4c, 0x24, 0x38, // 1004 mov [rsp + 0x38], r9
        0x4c, 0x89, 0x44, 0x24, 0x30, // 1009 mov [rsp + 0x30], r8
        0x48, 0x89, 0x54, 0x24, 0x28, // 100e mov [rsp + 0x28], rdx
        0x89, 0x4c, 0x24, 0x14, // 1013 mov [rsp + 0x14], ecx
        0x48, 0x8d, 0x44, 0x24, 0x28, // 1017 lea rax, [rsp + 0x28]: &home[1]
        0x48, 0x89, 0x44, 0x24, 0x08, // 101c mov [rsp + 0x8], rax: ap
        0xc7, 0x44, 0x24, 0x04, 0, 0, 0, 0, // 1021 mov dword [rsp + 0x4], 0: total
        0xc7, 0x04, 0x24, 0, 0, 0, 0, // 1029 mov dword [rsp], 0: i
        0x8b, 0x04, 0x24, // 1030 mov eax, [rsp]
        0x3b, 0x44, 0x24, 0x14, // 1033 cmp eax, [rsp + 0x14]
        0x0f, 0x8d, 0x29, 0, 0, 0, // 1037 jge 0x1066
        0x48, 0x8b, 0x44, 0x24, 0x08, // 103d mov rax, [rsp + 0x8]
        0x48, 0x89, 0xc1, // 1042 mov rcx, rax
        0x48, 0x83, 0xc1, step, // 1045 add rcx, step
        0x48, 0x89, 0x4c, 0x24, 0x08, // 1049 mov [rsp + 0x8], rcx
        0x8b, 0x00, // 104e mov eax, [rax]
        0x03, 0x44, 0x24, 0x04, // 1050 add eax, [rsp + 0x4]
        0x89, 0x44, 0x24, 0x04, // 1054 mov [rsp + 0x4], eax
        0x8b, 0x04, 0x24, // 1058 mov eax, [rsp]
        0x83, 0xc0, 0x01, // 105b add eax, 1
        0x89, 0x04, 0x24, // 105e mov [rsp], eax
        0xe9, 0xca, 0xff, 0xff, 0xff, // 1061 jmp 0x1030
        0x8b, 0x44, 0x24, 0x04, // 1066 mov eax, [rsp + 0x4]
        0x48, 0x83, 0xc4, 0x18, // 106a add rsp, 0x18
        0xc3, // 106e ret
        0x90, // 106f nop
        0x48, 0x83, 0xec, 0x28, // 1070 sub rsp, 0x28
        0xb9, 0x03, 0, 0, 0, // 1074 mov ecx, 3
        0xba, 0x01, 0, 0, 0, // 1079 mov edx, 1
        0x41, 0xb8, 0x02, 0, 0, 0, // 107e mov r8d, 2
        0x41, 0xb9, 0x03, 0, 0, 0, // 1084 mov r9d, 3
        0xe8, 0x71, 0xff, 0xff, 0xff, // 108a call 0x1000
        0x48, 0x83, 0xc4, 0x28, // 108f add rsp, 0x28
        0xc3, // 1093 ret
    ];
    code.resize(0xa0, 0xcc);
    Box::leak(code.into_boxed_slice())
}

fn sum(step: u8) -> OpenProgram<Literal> {
    let functions = [("sum", BASE, 0x70), ("caller", BASE + 0x70, 0x24)];
    OpenProgram::of(Literal::of_code(summing(step), &functions).pe())
}

/// A body that walks its own home `va_list` one slot per trip, `n` times, takes a tail its first
/// parameter counts: the caller's constant 3 passes three more (ADR "Count-driven tail").
#[test]
fn a_home_cursor_counted_by_a_parameter_is_a_counted_tail() {
    let mut open = sum(8);
    let callee = rendered(&mut open, BASE);
    assert!(
        callee.contains("sum(") && callee.contains(", ...)"),
        "{callee}"
    );
    let caller = rendered(&mut open, BASE + 0x70);
    let arguments = common::call_arguments(&caller, "sum").unwrap_or_else(|| panic!("{caller}"));
    let bare = arguments
        .iter()
        .map(|argument| common::bare(argument).trim_end_matches('U'))
        .collect::<Vec<_>>();
    assert_eq!(bare, ["3", "1", "2", "3"], "{caller}");
}

/// The same walk stepping by 4: a trip reads past its own slot, so no count bounds the tail.
#[test]
fn a_home_cursor_stepping_other_than_a_slot_is_no_counted_tail() {
    let mut open = sum(4);
    let callee = rendered(&mut open, BASE);
    assert!(!callee.contains("..."), "{callee}");
    let caller = rendered(&mut open, BASE + 0x70);
    let arguments = common::call_arguments(&caller, "sum");
    assert!(
        arguments.is_none_or(|arguments| arguments.len() != 4),
        "{caller}"
    );
}
