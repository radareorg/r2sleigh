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

/// `q = p->f_38; q->f_1, q->f_8 read, q->f_10 written`: `q`'s record (ADR test 4, D644).
const LOADED: &[u8] = &[
    0x48, 0x8b, 0x47, 0x38, // 1000 mov rax, [rdi + 0x38]
    0x8b, 0x48, 0x08, // 1004 mov ecx, [rax + 8]
    0x0f, 0xb6, 0x50, 0x01, // 1007 movzx edx, byte [rax + 1]
    0x48, 0x89, 0x48, 0x10, // 100b mov [rax + 0x10], rcx
    0x01, 0xd0, // 100f add eax, edx
    0xc3, // 1011 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1012 padding
];

/// The same reads through a pointer the caller left on the stack: no store proven to reach it.
const RELOADED: &[u8] = &[
    0x48, 0x8b, 0x44, 0x24, 0x08, // 1000 mov rax, [rsp + 8]
    0x8b, 0x48, 0x08, // 1005 mov ecx, [rax + 8]
    0x0f, 0xb6, 0x50, 0x01, // 1008 movzx edx, byte [rax + 1]
    0x01, 0xd1, // 100c add ecx, edx
    0x89, 0xc8, // 100e mov eax, ecx
    0xc3, // 1010 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1011 padding
];

/// `p = c ? p->next : p; return p->a`: the parameter and the pointer its field holds merge, so
/// the record's pointer field leads back to it (ADR test 6, refusing half).
const LIST_STEP: &[u8] = &[
    0x48, 0x8b, 0x47, 0x08, // 1000 mov rax, [rdi + 8]
    0x8b, 0x08, // 1004 mov ecx, [rax]
    0x85, 0xf6, // 1006 test esi, esi
    0x74, 0x03, // 1008 je 0x100d
    0x48, 0x89, 0xc7, // 100a mov rdi, rax
    0x0f, 0xb6, 0x07, // 100d movzx eax, byte [rdi]
    0x01, 0xc8, // 1010 add eax, ecx
    0xc3, // 1012 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, // 1013 padding
];

/// ADR test 4: a pointer loaded from a parameter's field has a record; its accesses are members.
#[test]
fn a_pointer_loaded_from_a_field_has_a_record() {
    let text = rendered(LOADED, 0x12);
    for member in ["f_1;", "f_8;", "f_10;"] {
        assert!(text.contains(member), "{member}: {text}");
    }
    assert!(text.contains("->f_8)"), "{text}");
}

/// ADR test 5: a pointer reloaded from a slot no proven store reaches has no record.
#[test]
fn a_reloaded_pointer_with_no_proven_store_has_no_record() {
    let text = rendered(RELOADED, 0x11);
    assert!(!text.contains("->f_"), "{text}");
}

/// ADR test 6: a record whose pointer field leads back to it is refused, with the reason.
#[test]
fn a_record_its_pointer_field_leads_back_to_is_refused() {
    let text = rendered(LIST_STEP, 0x13);
    assert!(!text.contains("->f_"), "{text}");
    assert!(text.contains("(Recursive)"), "{text}");
}
