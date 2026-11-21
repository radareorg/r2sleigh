//! Records laid out from each access's place, span by span (doc/adr-memory-places.md, D643).

use crate::common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;

/// `f` at `BASE`, `len` bytes, rendered after `aa`.
fn rendered(code: &'static [u8], len: u64) -> String {
    let program = Literal::of_code(code, &[("f", BASE, len)]);
    let mut open = OpenProgram::of(program);
    open.analyse_program().expect("it surveys");
    let rendering = open.rendered(BASE).expect("it renders");
    rendering.response.output.into_text()
}

/// `int f(struct s *p, long i) { return p->a + p->b + p->c[i]; }`, `a` 4 bytes at 0, `b` 1 at 8.
const INDEXED_BESIDE_FIELDS: &[u8] = &[
    0x8b, 0x07, // 1000 mov eax, [rdi]
    0x0f, 0xb6, 0x57, 0x08, // 1002 movzx edx, byte [rdi + 8]
    0x01, 0xd0, // 1006 add eax, edx
    0x03, 0x44, 0xb7, 0x10, // 1008 add eax, [rdi + rsi*4 + 0x10]
    0xc3, // 100c ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, // 100d padding
];

/// `{4@0, 8@8}` read, and the 16 bytes at 0 copied to `rsi`: the copy is a span over both.
const SPAN: &[u8] = &[
    0x8b, 0x07, // 1000 mov eax, [rdi]
    0x48, 0x03, 0x47, 0x08, // 1002 add rax, [rdi + 8]
    0x0f, 0x10, 0x0f, // 1006 movups xmm1, [rdi]
    0x0f, 0x11, 0x0e, // 1009 movups [rsi], xmm1
    0xc3, // 100c ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, // 100d padding
];

/// `{8@0, 4@4}`: the 8-byte read starts inside no member but before `f_4`; it alone is refused.
const INTERIOR: &[u8] = &[
    0x48, 0x8b, 0x07, // 1000 mov rax, [rdi]
    0x03, 0x47, 0x04, // 1003 add eax, [rdi + 4]
    0xc3, // 1006 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, // 1007 padding
];

/// `argv[1] + argv[2] + argv[3]`: one width, as much an array as a record.
const ARGV: &[u8] = &[
    0x48, 0x8b, 0x47, 0x08, // 1000 mov rax, [rdi + 8]
    0x48, 0x03, 0x47, 0x10, // 1004 add rax, [rdi + 0x10]
    0x48, 0x03, 0x47, 0x18, // 1008 add rax, [rdi + 0x18]
    0xc3, // 100c ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, // 100d padding
];

/// ADR test 1: one indexed access no longer refuses the parameter's constant fields.
#[test]
fn an_indexed_access_leaves_the_constant_fields_members() {
    let text = rendered(INDEXED_BESIDE_FIELDS, 0xd);
    assert!(text.contains("&arg0->f_0"), "{text}");
    assert!(text.contains("&arg0->f_8"), "{text}");
}

/// ADR test 2: a wide copy over members leaves both members standing; the record states it a
/// span at `f_0` (r2types `records::tests`), spelled at the member's address by D671.
#[test]
fn a_copy_over_members_leaves_the_members() {
    let text = rendered(SPAN, 0xd);
    assert!(text.contains("&arg0->f_0"), "{text}");
    assert!(text.contains("&arg0->f_8"), "{text}");
    assert!(text.contains("uint8_t _pad_4[4];"), "{text}");
}

/// ADR test 2: an access that starts before a member is refused alone; the member stands.
#[test]
fn an_interior_access_refuses_only_itself() {
    let text = rendered(INTERIOR, 0x7);
    assert!(text.contains("&arg0->f_4"), "{text}");
    assert!(!text.contains("&arg0->f_0"), "{text}");
}

/// ADR test 7: `argv[1..3]` is one width and lays out no record.
#[test]
fn argv_lays_out_no_record() {
    let text = rendered(ARGV, 0xd);
    assert!(!text.contains("struct fcn_"), "{text}");
}
