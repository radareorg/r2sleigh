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
