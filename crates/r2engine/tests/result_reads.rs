//! A body that writes both result registers returns the one its callers read
//! (doc/adr-resolved-bodies.md, "Caller reads").

mod common;

use common::{BASE, Literal};
use r2engine::RenderTier;
use r2engine::program::OpenProgram;

/// `pxor xmm0, xmm0; mov eax, 7; ret`, as vectorized integer code leaves XMM0 written, then
/// `call f; mov [rsi], eax; ret`, which reads EAX as the call left it.
const READ_AS_INTEGER: &[u8] = &[
    0x66, 0x0f, 0xef, 0xc0, // 1000 pxor xmm0, xmm0
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1004 mov eax, 7
    0xc3, // 1009 ret
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 100a padding
    0xe8, 0xeb, 0xff, 0xff, 0xff, // 1010 call 0x1000
    0x89, 0x06, // 1015 mov [rsi], eax
    0xc3, // 1017 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1018 padding
];

fn rendered(program: Literal, tier: RenderTier) -> String {
    OpenProgram::of(program)
        .rendered(BASE, tier)
        .expect("it renders")
        .response
        .output
        .into_text()
}

#[test]
fn a_caller_reading_the_integer_register_decides_the_result() {
    let program = || {
        Literal::of_code(
            READ_AS_INTEGER,
            &[("f", BASE, 0x0a), ("caller", BASE + 0x10, 0x08)],
        )
    };
    for tier in [RenderTier::C, RenderTier::Staged] {
        let text = rendered(program(), tier);
        assert!(text.starts_with("uint64_t f("), "{tier:?}: {text}");
        assert!(text.contains("7"), "{tier:?}: {text}");
        assert!(!text.contains("r2sleigh_residual"), "{tier:?}: {text}");
    }
}

/// The same body with no call to it: nothing says which register is its result.
#[test]
fn without_a_reading_call_the_result_stays_a_residual() {
    let program = || Literal::of_code(READ_AS_INTEGER, &[("f", BASE, 0x0a)]);
    for tier in [RenderTier::C, RenderTier::Staged] {
        let text = rendered(program(), tier);
        assert!(
            text.contains("return r2sleigh_residual_"),
            "{tier:?}: {text}"
        );
    }
}
