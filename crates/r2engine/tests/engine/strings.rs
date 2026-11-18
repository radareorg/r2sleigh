//! Text a line points at: stated where an owner states the use, an unknown where only a constant
//! is moved, nothing where arithmetic reads it or an `adrp` forms only a page (ROADMAP D571).

use crate::common;
use common::{BASE, Literal, PLT_CALLER};
use r2engine::program::OpenProgram;
use r2engine::query::{AnnotationKind, Line, Mark};

/// `.plt`, then at `PLT_CALLER` one instruction naming 0x10a0, `mov eax, 0`, `call stub`, `ret`,
/// and `"%d %d"` at 0x10a0, where `Literal::with_data` states a data section.
const fn naming(first: [u8; 5]) -> [u8; 0xa8] {
    let mut text = [0u8; 0x88];
    let code = [
        first[0], first[1], first[2], first[3], first[4], // 1020 the instruction
        0xb8, 0x00, 0x00, 0x00, 0x00, // 1025 mov eax, 0
        0xe8, 0xe1, 0xff, 0xff, 0xff, // 102a call stub
        0xc3, // 102f ret
    ];
    let mut at = 0;
    while at < code.len() {
        text[at] = code[at];
        at += 1;
    }
    let format = *b"%d %d\0";
    while at - code.len() < format.len() {
        text[0x80 + at - code.len()] = format[at - code.len()];
        at += 1;
    }
    common::plt_then(&text)
}

const FORMAT: u64 = BASE + 0xa0;
const MOVES_TO_ESI: [u8; 0xa8] = naming([0xbe, 0xa0, 0x10, 0x00, 0x00]);
const MASKS_EAX: [u8; 0xa8] = naming([0x25, 0xa0, 0x10, 0x00, 0x00]);
const MOVES_TO_EDI: [u8; 0xa8] = naming([0xbf, 0xa0, 0x10, 0x00, 0x00]);

/// The first line's text notes and each one's mark, calling `import`.
fn noted(import: &str, code: &'static [u8; 0xa8]) -> Vec<(AnnotationKind, Mark)> {
    let literal = Literal::plt_wrapped(import, code).with_data();
    let listing = OpenProgram::of(literal).function_listing(PLT_CALLER);
    let lines: Vec<Line> = listing.expect("it lists").lines.value;
    let first = lines.iter().find(|line| line.address == PLT_CALLER);
    let annotations = first.expect("the first line").annotations.iter();
    annotations
        .filter(|annotation| {
            matches!(
                annotation.kind,
                AnnotationKind::Text { .. } | AnnotationKind::TextIfAddress { .. }
            )
        })
        .map(|annotation| (annotation.kind.clone(), annotation.mark()))
        .collect()
}

/// bomb 0x400f51: the format handed to `sscanf`, whose arguments are refused, is moved whole into
/// `esi`; its text is an unknown, `? "%d %d"`, no claim that the number is an address.
#[test]
fn a_moved_constant_no_owner_uses_reads_as_text_if_it_is_an_address() {
    let text = AnnotationKind::TextIfAddress {
        address: FORMAT,
        text: "%d %d".to_owned(),
    };
    assert_eq!(
        noted("__isoc99_sscanf", &MOVES_TO_ESI),
        [(text, Mark::Unknown)]
    );
}

/// bash 0x1f8b2: a mask is arithmetic on the number, so its bytes say nothing.
#[test]
fn a_constant_arithmetic_reads_gets_no_text() {
    assert_eq!(noted("__isoc99_sscanf", &MASKS_EAX), []);
}

/// A declared `printf` states its format a pointer: the text is the declaration's, `^`.
#[test]
fn a_constant_a_declared_pointer_parameter_takes_keeps_its_text() {
    let text = AnnotationKind::Text {
        address: FORMAT,
        text: "%d %d".to_owned(),
    };
    assert_eq!(noted("printf", &MOVES_TO_EDI), [(text, Mark::Declared)]);
}

/// `adrp x0, 0x2000; add x0, x0, #0x50; ret`, the page reading `"page"` and the address
/// `"done"`: the page is no address until the `add` completes it (ls-toybox `seq_main`).
const PAGED: [u8; 0x1060] = {
    let mut bytes = [0u8; 0x1060];
    let code = [
        0x00, 0x00, 0x00, 0xb0, 0x00, 0x40, 0x01, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let mut at = 0;
    while at < code.len() {
        bytes[at] = code[at];
        at += 1;
    }
    let page = *b"page\0";
    let done = *b"done\0";
    at = 0;
    while at < 5 {
        bytes[0x1000 + at] = page[at];
        bytes[0x1050 + at] = done[at];
        at += 1;
    }
    bytes
};

#[test]
fn an_adrp_page_holds_no_text_and_the_address_its_add_completes_does() {
    let literal = Literal::of_code(&PAGED, &[("paged", BASE, 12)])
        .in_aarch64()
        .with_data_after(BASE + 0x1000);
    let listing = OpenProgram::of(literal).function_listing(BASE);
    let lines: Vec<Line> = listing.expect("it lists").lines.value;
    let texts = |line: &Line| {
        (line.annotations.iter())
            .filter_map(|annotation| match &annotation.kind {
                AnnotationKind::Text { address, text }
                | AnnotationKind::TextIfAddress { address, text } => Some((*address, text.clone())),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(texts(&lines[0]), [], "{:?}", lines[0].annotations);
    assert_eq!(texts(&lines[1]), [(BASE + 0x1050, "done".to_owned())]);
}
