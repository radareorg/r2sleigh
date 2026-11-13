//! A parameter's sign and width are what its body's reads state, spelled once for `pdd` and `afi`
//! (ROADMAP D265, D266, S29).

use crate::common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;
use r2types::{CTypeLike, Signedness};

/// `f`'s rendering and each parameter's type as `afi` states it.
fn header_and_types(code: &'static [u8]) -> (String, Vec<CTypeLike>) {
    let size = code.len() as u64;
    let mut program = OpenProgram::of(Literal::of_code(code, &[("f", BASE, size)]));
    let text = (program.rendered(BASE).expect("it renders").response.output).into_text();
    let info = program.function_info(BASE).expect("it is analysed");
    let types = (info.arguments.iter()).map(|argument| argument.ty.value.clone());
    (text, types.collect())
}

fn word(bits: u32) -> CTypeLike {
    r2types::unstated_word(bits)
}

/// gcc -O2 `int sdiv7(int x) { return x / 7; }`: the lane is sign-extended and shifted
/// arithmetically, and nothing reads it unsigned.
const SDIV7: &[u8] = &[
    0x48, 0x63, 0xc7, // 1000 movsxd rax, edi
    0x89, 0xfa, // 1003 mov edx, edi
    0x48, 0x69, 0xc0, 0x93, 0x24, 0x49, 0x92, // 1005 imul rax, rax, -1840700269
    0xc1, 0xfa, 0x1f, // 100c sar edx, 31
    0x48, 0xc1, 0xe8, 0x20, // 100f shr rax, 32
    0x01, 0xf8, // 1013 add eax, edi
    0xc1, 0xf8, 0x02, // 1015 sar eax, 2
    0x29, 0xd0, // 1018 sub eax, edx
    0xc3, // 101a ret
    0x90, 0x90, 0x90, 0x90, 0x90, // 101b padding
];

#[test]
fn a_signed_division_declares_its_parameter_signed() {
    let (text, types) = header_and_types(SDIV7);
    let signed = CTypeLike::Int {
        bits: 32,
        signedness: Signedness::Signed,
    };
    assert_eq!(types, [signed], "{text}");
    assert!(text.contains("(int32_t arg0)"), "{text}");
}

/// `seven.c`'s body only adds: `lea eax, [rdi + rsi]`. Addition reads no sign.
const ADDS: &[u8] = &[
    0x8d, 0x04, 0x37, // 1000 lea eax, [rdi + rsi]
    0xc3, // 1003 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // padding
];

#[test]
fn an_added_parameter_states_no_sign() {
    let (text, types) = header_and_types(ADDS);
    assert_eq!(types, [word(32), word(32)], "{text}");
    assert!(
        text.contains("(r2sleigh_word_u32 arg0, r2sleigh_word_u32 arg1)"),
        "{text}"
    );
}

/// `and edi, 1; mov [rsi], edi`: the mask demands one byte of `edi` and reads all four.
const MASKED: &[u8] = &[
    0x83, 0xe7, 0x01, // 1000 and edi, 1
    0x89, 0x3e, // 1003 mov [rsi], edi
    0xc3, // 1005 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // padding
];

#[test]
fn a_parameter_masked_to_one_bit_is_as_wide_as_the_and() {
    let (text, types) = header_and_types(MASKED);
    assert_eq!(types.first(), Some(&word(32)), "{text}");
    assert!(text.contains("(r2sleigh_word_u32 arg0,"), "{text}");
}

/// `mov eax, edi; shr eax, 31`: gcc's signed division by a power of two reads the sign bit this
/// way, so a logical shift is no evidence the value is unsigned (RULING 3).
const SIGN_BIT: &[u8] = &[
    0x89, 0xf8, // 1000 mov eax, edi
    0xc1, 0xe8, 0x1f, // 1002 shr eax, 31
    0xc3, // 1005 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // padding
];

#[test]
fn a_logical_shift_by_the_sign_bit_states_no_sign() {
    let (text, types) = header_and_types(SIGN_BIT);
    assert_eq!(types, [word(32)], "{text}");
    assert!(!text.contains("uint32_t arg0"), "{text}");
}
