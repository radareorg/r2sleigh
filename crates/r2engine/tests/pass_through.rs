//! A body that hands its own argument register to a call, unwritten, does not prove it takes no
//! argument: prepared alone it cannot see what the call reads.

mod common;

use common::{BASE, Literal};
use r2engine::RenderTier;
use r2engine::program::OpenProgram;

/// `f`: `call g; mov eax, 1; ret`, handing on the `rdi` it arrived with; `g`: `mov eax, [rdi]; ret`;
/// `caller`: `mov edi, 5; call f; ret`.
const HANDED_ON: &[u8] = &[
    0xe8, 0x0b, 0x00, 0x00, 0x00, // 1000 call 0x1010
    0xb8, 0x01, 0x00, 0x00, 0x00, // 1005 mov eax, 1
    0xc3, // 100a ret
    0x90, 0x90, 0x90, 0x90, 0x90, // 100b padding
    0x8b, 0x07, // 1010 mov eax, [rdi]
    0xc3, // 1012 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1013 padding
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1020 mov edi, 5
    0xe8, 0xd6, 0xff, 0xff, 0xff, // 1025 call 0x1000
    0xc3, // 102a ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 102b padding
];

/// The caller's call to `f` was written `f()`, dropping the 5 `g` reads. `f` hands its `rdi` to `g`
/// unwritten, so `f` is resolved again with `g`, which states what it reads: `f(5)`.
#[test]
fn a_call_to_a_body_that_hands_on_its_argument_passes_it() {
    for tier in [RenderTier::C, RenderTier::Staged] {
        let text = OpenProgram::of(Literal::of_code(
            HANDED_ON,
            &[
                ("f", BASE, 0x0b),
                ("g", BASE + 0x10, 0x03),
                ("caller", BASE + 0x20, 0x0b),
            ],
        ))
        .rendered(BASE + 0x20, tier)
        .expect("it renders")
        .response
        .output
        .into_text();
        assert!(
            text.contains("f(5)") || text.contains("f((uint64_t)5U)"),
            "{tier:?}: {text}"
        );
        assert!(!text.contains("f()"), "{tier:?}: {text}");
        assert!(!text.contains("r2sleigh_residual"), "{tier:?}: {text}");
    }
}

/// `f` increments `*rdi`, keeps the `rsi` it arrived with in `rbx`, and hands `rbx + 1` to a
/// call through memory, `rdi` as it arrived, and returns 7: the call's arity is unproven at its
/// first slot, so it observes nothing it is handed. `caller`: `mov edi, 3; mov esi, 5; call f`.
const KEPT_FOR_AN_UNPROVEN_CALL: &[u8] = &[
    0x53, // 1000 push rbx
    0x48, 0x89, 0xf3, // 1001 mov rbx, rsi
    0x48, 0x83, 0x07, 0x01, // 1004 add qword [rdi], 1
    0x48, 0x8d, 0x73, 0x01, // 1008 lea rsi, [rbx + 1]
    0xba, 0x07, 0x00, 0x00, 0x00, // 100c mov edx, 7
    0xff, 0x14, 0x25, 0x00, 0x20, 0x00, 0x00, // 1011 call [0x2000]
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1018 mov eax, 7
    0x5b, // 101d pop rbx
    0xc3, // 101e ret
    0xcc, // 101f padding
    0xbf, 0x03, 0x00, 0x00, 0x00, // 1020 mov edi, 3
    0xbe, 0x05, 0x00, 0x00, 0x00, // 1025 mov esi, 5
    0xe8, 0xd1, 0xff, 0xff, 0xff, // 102a call 0x1000
    0xc3, // 102f ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1030 padding
];

/// `f` reads `rsi` only to compute what it hands a call of unproven arity, which no obligation
/// observes: its parameters are a floor, and the caller passes the 5 it wrote.
#[test]
fn a_register_kept_for_a_call_of_unproven_arity_is_passed() {
    for tier in [RenderTier::C, RenderTier::Staged] {
        let text = OpenProgram::of(Literal::of_code(
            KEPT_FOR_AN_UNPROVEN_CALL,
            &[("f", BASE, 0x1f), ("caller", BASE + 0x20, 0x10)],
        ))
        .rendered(BASE + 0x20, tier)
        .expect("it renders")
        .response
        .output
        .into_text();
        assert!(
            text.contains("f(3, 5)") || text.contains("f((uint64_t)3U, (uint64_t)5U)"),
            "{tier:?}: {text}"
        );
    }
}
