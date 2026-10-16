//! A cycle's results are their least fixpoint over return values, and an unproven result states
//! its causes (ROADMAP P7, D37): the paths of a member's own seed it, and its own read decides.

use crate::common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;
use r2ssa::{SourceResultCause, SourceUnstatedCall};

/// `root` rendered once `aa` surveyed the program.
fn surveyed(code: &'static [u8], functions: &[(&str, u64, u64)], root: u64) -> String {
    let mut open = OpenProgram::of(Literal::of_code(code, functions));
    open.analyse_program().expect("it surveys");
    open.rendered(root)
        .expect("it renders")
        .response
        .output
        .into_text()
}

/// gcc -O1's `shape_mutual_even` and `shape_mutual_odd`: each returns its partner's `rax` after
/// `call partner; add rsp, 8; ret`, and `rax ^ rsi` on a path of its own; `caller` calls `even`.
const MUTUAL_U64: &[u8] = &[
    0x48, 0x85, 0xff, // 1000 test rdi, rdi
    0x75, 0x09, // 1003 jne 0xe <even+0xe>
    0xb8, 0xa5, 0xa5, 0xa5, 0xa5, // 1005 mov eax, 0xa5a5a5a5
    0x48, 0x31, 0xf0, // 100a xor rax, rsi
    0xc3, // 100d ret
    0x48, 0x83, 0xec, 0x08, // 100e sub rsp, 0x8
    0x48, 0x89, 0xf0, // 1012 mov rax, rsi
    0x48, 0xc1, 0xe0, 0x05, // 1015 shl rax, 0x5
    0x48, 0x29, 0xf0, // 1019 sub rax, rsi
    0x48, 0x8d, 0x34, 0x38, // 101c lea rsi, [rax + rdi]
    0x48, 0x83, 0xef, 0x01, // 1020 sub rdi, 0x1
    0xe8, 0x05, 0x00, 0x00, 0x00, // 1024 call 0x2e <odd>
    0x48, 0x83, 0xc4, 0x08, // 1029 add rsp, 0x8
    0xc3, // 102d ret
    0x48, 0x85, 0xff, // 102e test rdi, rdi
    0x75, 0x09, // 1031 jne 0x3c <odd+0xe>
    0xb8, 0x5a, 0x5a, 0x5a, 0x5a, // 1033 mov eax, 0x5a5a5a5a
    0x48, 0x31, 0xf0, // 1038 xor rax, rsi
    0xc3, // 103b ret
    0x48, 0x83, 0xec, 0x08, // 103c sub rsp, 0x8
    0x48, 0x89, 0xf0, // 1040 mov rax, rsi
    0x48, 0xc1, 0xe0, 0x04, // 1043 shl rax, 0x4
    0x48, 0x01, 0xf0, // 1047 add rax, rsi
    0x48, 0x8d, 0x34, 0xb8, // 104a lea rsi, [rax + 4*rdi]
    0x48, 0x83, 0xef, 0x01, // 104e sub rdi, 0x1
    0xe8, 0xa9, 0xff, 0xff, 0xff, // 1052 call 0x0 <even>
    0x48, 0x83, 0xc4, 0x08, // 1057 add rsp, 0x8
    0xc3, // 105b ret
    0xcc, // 105c padding
    0xcc, // 105d padding
    0xcc, // 105e padding
    0xcc, // 105f padding
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1060 mov edi, 0x5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1065 mov esi, 0x7
    0xe8, 0x91, 0xff, 0xff, 0xff, // 106a call 0x0 <even>
    0xc3, // 106f ret
];

/// The same pair over `int`: the paths of their own write `eax` alone.
const MUTUAL_INT: &[u8] = &[
    0x48, 0x85, 0xff, // 1000 test rdi, rdi
    0x75, 0x08, // 1003 jne 0xd <even+0xd>
    0xb8, 0xa5, 0xa5, 0xa5, 0xa5, // 1005 mov eax, 0xa5a5a5a5
    0x31, 0xf0, // 100a xor eax, esi
    0xc3, // 100c ret
    0x48, 0x83, 0xec, 0x08, // 100d sub rsp, 0x8
    0x89, 0xf0, // 1011 mov eax, esi
    0xc1, 0xe0, 0x05, // 1013 shl eax, 0x5
    0x29, 0xf0, // 1016 sub eax, esi
    0x8d, 0x34, 0x38, // 1018 lea esi, [rax + rdi]
    0x48, 0x83, 0xef, 0x01, // 101b sub rdi, 0x1
    0xe8, 0x05, 0x00, 0x00, 0x00, // 101f call 0x29 <odd>
    0x48, 0x83, 0xc4, 0x08, // 1024 add rsp, 0x8
    0xc3, // 1028 ret
    0x48, 0x85, 0xff, // 1029 test rdi, rdi
    0x75, 0x08, // 102c jne 0x36 <odd+0xd>
    0xb8, 0x5a, 0x5a, 0x5a, 0x5a, // 102e mov eax, 0x5a5a5a5a
    0x31, 0xf0, // 1033 xor eax, esi
    0xc3, // 1035 ret
    0x48, 0x83, 0xec, 0x08, // 1036 sub rsp, 0x8
    0x89, 0xf0, // 103a mov eax, esi
    0xc1, 0xe0, 0x04, // 103c shl eax, 0x4
    0x01, 0xf0, // 103f add eax, esi
    0x8d, 0x34, 0xb8, // 1041 lea esi, [rax + 4*rdi]
    0x48, 0x83, 0xef, 0x01, // 1044 sub rdi, 0x1
    0xe8, 0xb3, 0xff, 0xff, 0xff, // 1048 call 0x0 <even>
    0x48, 0x83, 0xc4, 0x08, // 104d add rsp, 0x8
    0xc3, // 1051 ret
    0xcc, // 1052 padding
    0xcc, // 1053 padding
    0xcc, // 1054 padding
    0xcc, // 1055 padding
    0xcc, // 1056 padding
    0xcc, // 1057 padding
    0xcc, // 1058 padding
    0xcc, // 1059 padding
    0xcc, // 105a padding
    0xcc, // 105b padding
    0xcc, // 105c padding
    0xcc, // 105d padding
    0xcc, // 105e padding
    0xcc, // 105f padding
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1060 mov edi, 0x5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1065 mov esi, 0x7
    0xe8, 0x91, 0xff, 0xff, 0xff, // 106a call 0x0 <even>
    0xc3, // 106f ret
];

/// A pair whose base path returns without writing `rax`: no path returns a value of its own.
const MUTUAL_UNTOUCHED_BASE: &[u8] = &[
    0x48, 0x85, 0xff, // 1000 test rdi, rdi
    0x74, 0x11, // 1003 je 0x16 <even+0x16>
    0x48, 0x83, 0xec, 0x08, // 1005 sub rsp, 0x8
    0x48, 0x83, 0xef, 0x01, // 1009 sub rdi, 0x1
    0xe8, 0x05, 0x00, 0x00, 0x00, // 100d call 0x17 <odd>
    0x48, 0x83, 0xc4, 0x08, // 1012 add rsp, 0x8
    0xc3, // 1016 ret
    0x48, 0x85, 0xff, // 1017 test rdi, rdi
    0x74, 0x11, // 101a je 0x2d <odd+0x16>
    0x48, 0x83, 0xec, 0x08, // 101c sub rsp, 0x8
    0x48, 0x83, 0xef, 0x01, // 1020 sub rdi, 0x1
    0xe8, 0xd7, 0xff, 0xff, 0xff, // 1024 call 0x0 <even>
    0x48, 0x83, 0xc4, 0x08, // 1029 add rsp, 0x8
    0xc3, // 102d ret
    0xcc, // 102e padding
    0xcc, // 102f padding
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1030 mov edi, 0x5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1035 mov esi, 0x7
    0xe8, 0xc1, 0xff, 0xff, 0xff, // 103a call 0x0 <even>
    0xc3, // 103f ret
];

/// `even` returns a value of its own or `odd`'s; `odd` returns `call [rsi]`'s or `even`'s.
const MUTUAL_INDIRECT_BASE: &[u8] = &[
    0x48, 0x85, 0xff, // 1000 test rdi, rdi
    0x75, 0x09, // 1003 jne 0xe <even+0xe>
    0xb8, 0xa5, 0xa5, 0xa5, 0xa5, // 1005 mov eax, 0xa5a5a5a5
    0x48, 0x31, 0xf0, // 100a xor rax, rsi
    0xc3, // 100d ret
    0x48, 0x83, 0xec, 0x08, // 100e sub rsp, 0x8
    0x48, 0x83, 0xef, 0x01, // 1012 sub rdi, 0x1
    0xe8, 0x05, 0x00, 0x00, 0x00, // 1016 call 0x20 <odd>
    0x48, 0x83, 0xc4, 0x08, // 101b add rsp, 0x8
    0xc3, // 101f ret
    0x48, 0x85, 0xff, // 1020 test rdi, rdi
    0x75, 0x0b, // 1023 jne 0x30 <odd+0x10>
    0x48, 0x83, 0xec, 0x08, // 1025 sub rsp, 0x8
    0xff, 0x16, // 1029 call qword ptr [rsi]
    0x48, 0x83, 0xc4, 0x08, // 102b add rsp, 0x8
    0xc3, // 102f ret
    0x48, 0x83, 0xec, 0x08, // 1030 sub rsp, 0x8
    0x48, 0x83, 0xef, 0x01, // 1034 sub rdi, 0x1
    0xe8, 0xc3, 0xff, 0xff, 0xff, // 1038 call 0x0 <even>
    0x48, 0x83, 0xc4, 0x08, // 103d add rsp, 0x8
    0xc3, // 1041 ret
    0xcc, // 1042 padding
    0xcc, // 1043 padding
    0xcc, // 1044 padding
    0xcc, // 1045 padding
    0xcc, // 1046 padding
    0xcc, // 1047 padding
    0xcc, // 1048 padding
    0xcc, // 1049 padding
    0xcc, // 104a padding
    0xcc, // 104b padding
    0xcc, // 104c padding
    0xcc, // 104d padding
    0xcc, // 104e padding
    0xcc, // 104f padding
    0xbf, 0x05, 0x00, 0x00, 0x00, // 1050 mov edi, 0x5
    0xbe, 0x07, 0x00, 0x00, 0x00, // 1055 mov esi, 0x7
    0xe8, 0xa1, 0xff, 0xff, 0xff, // 105a call 0x0 <even>
    0xc3, // 105f ret
];

/// The same pair on AArch64, `x0` being both the argument and the result: gcc -O1's shape.
const MUTUAL_AARCH64: &[u8] = &[
    0xa0, 0x00, 0x00, 0xb5, // 1000 cbnz x0, 0x14 <even+0x14>
    0xa2, 0xb4, 0x94, 0xd2, // 1004 mov x2, #0xa5a5
    0xa2, 0xb4, 0xb4, 0xf2, // 1008 movk x2, #0xa5a5, lsl #16
    0x20, 0x00, 0x02, 0xca, // 100c eor x0, x1, x2
    0xc0, 0x03, 0x5f, 0xd6, // 1010 ret
    0xfd, 0x7b, 0xbf, 0xa9, // 1014 stp x29, x30, [sp, #-0x10]!
    0xfd, 0x03, 0x00, 0x91, // 1018 mov x29, sp
    0xe2, 0x03, 0x80, 0xd2, // 101c mov x2, #0x1f
    0x21, 0x00, 0x02, 0x9b, // 1020 madd x1, x1, x2, x0
    0x00, 0x04, 0x00, 0xd1, // 1024 sub x0, x0, #0x1
    0x03, 0x00, 0x00, 0x94, // 1028 bl 0x34 <odd>
    0xfd, 0x7b, 0xc1, 0xa8, // 102c ldp x29, x30, [sp], #0x10
    0xc0, 0x03, 0x5f, 0xd6, // 1030 ret
    0xa0, 0x00, 0x00, 0xb5, // 1034 cbnz x0, 0x48 <odd+0x14>
    0x42, 0x4b, 0x8b, 0xd2, // 1038 mov x2, #0x5a5a
    0x42, 0x4b, 0xab, 0xf2, // 103c movk x2, #0x5a5a, lsl #16
    0x20, 0x00, 0x02, 0xca, // 1040 eor x0, x1, x2
    0xc0, 0x03, 0x5f, 0xd6, // 1044 ret
    0xfd, 0x7b, 0xbf, 0xa9, // 1048 stp x29, x30, [sp, #-0x10]!
    0xfd, 0x03, 0x00, 0x91, // 104c mov x29, sp
    0x22, 0x02, 0x80, 0xd2, // 1050 mov x2, #0x11
    0x03, 0xf4, 0x7e, 0xd3, // 1054 lsl x3, x0, #2
    0x21, 0x0c, 0x02, 0x9b, // 1058 madd x1, x1, x2, x3
    0x00, 0x04, 0x00, 0xd1, // 105c sub x0, x0, #0x1
    0xe8, 0xff, 0xff, 0x97, // 1060 bl 0x0 <even>
    0xfd, 0x7b, 0xc1, 0xa8, // 1064 ldp x29, x30, [sp], #0x10
    0xc0, 0x03, 0x5f, 0xd6, // 1068 ret
    0x1f, 0x20, 0x03, 0xd5, // 106c nop
    0xfd, 0x7b, 0xbf, 0xa9, // 1070 stp x29, x30, [sp, #-0x10]!
    0xfd, 0x03, 0x00, 0x91, // 1074 mov x29, sp
    0xa0, 0x00, 0x80, 0xd2, // 1078 mov x0, #0x5
    0xe1, 0x00, 0x80, 0xd2, // 107c mov x1, #0x7
    0xe0, 0xff, 0xff, 0x97, // 1080 bl 0x0 <even>
    0xfd, 0x7b, 0xc1, 0xa8, // 1084 ldp x29, x30, [sp], #0x10
    0xc0, 0x03, 0x5f, 0xd6, // 1088 ret
];

const U64: [(&str, u64, u64); 3] = [
    ("even", BASE, 0x2e),
    ("odd", BASE + 0x2e, 0x2e),
    ("caller", BASE + 0x60, 0x10),
];
const INT: [(&str, u64, u64); 3] = [
    ("even", BASE, 0x29),
    ("odd", BASE + 0x29, 0x29),
    ("caller", BASE + 0x60, 0x10),
];
const UNTOUCHED: [(&str, u64, u64); 3] = [
    ("even", BASE, 0x17),
    ("odd", BASE + 0x17, 0x17),
    ("caller", BASE + 0x30, 0x10),
];
const INDIRECT: [(&str, u64, u64); 3] = [
    ("even", BASE, 0x20),
    ("odd", BASE + 0x20, 0x22),
    ("caller", BASE + 0x50, 0x10),
];

/// Each member returns its partner's result or one its own paths write: the result is the one
/// register both name, so neither return is a residual (`shape_mutual_even`, gcc -O1).
#[test]
fn under_aa_a_pair_returning_each_others_result_proves_it() {
    for at in [U64[0].1, U64[1].1, U64[2].1] {
        let text = surveyed(MUTUAL_U64, &U64, at);
        assert!(!text.contains("residual"), "{text}");
    }
    let text = surveyed(MUTUAL_U64, &U64, BASE);
    assert!(text.contains("rax_6 = odd("), "{text}");
    assert!(text.contains("return (uint64_t)rax_6;"), "{text}");
}

/// The paths of their own write `eax` alone, and the pair is proven all the same.
#[test]
fn under_aa_a_pair_over_int_proves_its_result() {
    for at in [INT[0].1, INT[1].1, INT[2].1] {
        let text = surveyed(MUTUAL_INT, &INT, at);
        assert!(!text.contains("residual"), "{text}");
    }
}

/// Without a survey the call is still a gap while the partner's arity is a floor, but the result
/// the cycle's members state each other is proven: the interface says so.
#[test]
fn a_cold_request_proves_a_cycle_through_a_floor_its_result() {
    let mut open = OpenProgram::of(Literal::of_code(MUTUAL_U64, &U64));
    for at in [BASE, BASE + 0x2e] {
        let prepared = open.prepared(at).expect("it prepares");
        let shared = prepared.artifact().shared_artifact();
        let interface = (shared.machine_context().function_interface()).expect("an interface");
        assert!(interface.unproven_result().is_none());
        assert!(interface.stated_result().is_some());
    }
}

/// The base path returns whatever the caller left in `rax`, which is no value the pair produces:
/// nothing seeds the fixpoint, and both results stay a visible residual.
#[test]
fn a_pair_with_no_path_of_its_own_stays_unproven() {
    for at in [UNTOUCHED[0].1, UNTOUCHED[1].1] {
        let text = surveyed(MUTUAL_UNTOUCHED_BASE, &UNTOUCHED, at);
        assert!(text.contains("r2sleigh_residual_u64"), "{text}");
    }
    let cause = result_cause(Literal::of_code(MUTUAL_UNTOUCHED_BASE, &UNTOUCHED), BASE);
    let partner = SourceResultCause::Returned(SourceUnstatedCall::Direct(BASE + 0x17));
    assert_eq!(cause, Some(vec![partner, SourceResultCause::HandedBack]));
}

/// `odd` returns what an indirect call returns, which no statement of a callee can prove: it
/// keeps its residual, and `even`, which returns `odd`'s, keeps its own.
#[test]
fn a_member_returning_an_indirect_call_keeps_the_pair_unproven() {
    for at in [INDIRECT[0].1, INDIRECT[1].1] {
        let text = surveyed(MUTUAL_INDIRECT_BASE, &INDIRECT, at);
        assert!(text.contains("r2sleigh_residual_u64"), "{text}");
    }
}

/// Why the function at `root` has no proven result, as recovery states it (ROADMAP D37).
fn result_cause(literal: Literal, root: u64) -> Option<Vec<SourceResultCause>> {
    let mut open = OpenProgram::of(literal);
    let prepared = open.prepared(root).expect("it prepares");
    let shared = prepared.artifact().shared_artifact();
    let interface = (shared.machine_context().function_interface()).expect("an interface");
    let unproven = interface.unproven_result()?;
    Some(unproven.causes().to_vec())
}

/// `f` at 0x1000 writes both result registers (`xor eax, eax; pxor xmm0, xmm0; ret`), so its
/// result is unproven; `code` sits at 0x1010, and the slot a call may go through at 0x1030.
const fn beside_both_registers<const N: usize>(code: [u8; N]) -> [u8; 0x30] {
    let mut bytes = [0xcc; 0x30];
    let f = [0x31, 0xc0, 0x66, 0x0f, 0xef, 0xc0, 0xc3];
    let mut at = 0;
    while at < f.len() {
        bytes[at] = f[at];
        at += 1;
    }
    at = 0;
    while at < N {
        bytes[0x10 + at] = code[at];
        at += 1;
    }
    bytes
}

const BOTH: [(&str, u64, u64); 2] = [("f", BASE, 7), ("g", BASE + 0x10, 6)];

/// `g`: `call f; ret`.
#[test]
fn a_call_to_a_callee_stating_no_result_is_a_result_returned_by_it() {
    const CODE: [u8; 0x30] = beside_both_registers([0xe8, 0xeb, 0xff, 0xff, 0xff, 0xc3]);
    let cause = result_cause(Literal::of_code(&CODE, &BOTH), BASE + 0x10);
    let callee = SourceUnstatedCall::Direct(BASE);
    assert_eq!(cause, Some(vec![SourceResultCause::Returned(callee)]));
}

/// `g`: `jmp f`.
#[test]
fn a_tail_jump_to_a_callee_stating_no_result_is_a_result_tailed_to_it() {
    const CODE: [u8; 0x30] = beside_both_registers([0xe9, 0xeb, 0xff, 0xff, 0xff]);
    let cause = result_cause(Literal::of_code(&CODE, &BOTH), BASE + 0x10);
    let callee = SourceUnstatedCall::Direct(BASE);
    assert_eq!(cause, Some(vec![SourceResultCause::Tailed(callee)]));
}

/// `g`: `call [rip + 0x1a]; ret`, through a slot the program may write.
#[test]
fn a_call_through_memory_is_a_result_returned_by_no_callee() {
    const CODE: [u8; 0x30] = beside_both_registers([0xff, 0x15, 0x1a, 0, 0, 0, 0xc3]);
    let literal = Literal::of_code(&CODE, &BOTH).writable_data_after(BASE + 0x20);
    let cause = result_cause(literal, BASE + 0x10);
    assert_eq!(
        cause,
        Some(vec![SourceResultCause::Returned(
            SourceUnstatedCall::Indirect
        )])
    );
}

/// `test edi, edi; je g2; jmp g1; g2: jmp g2'`: `g1` returns in `rax`, `g2` returns nothing.
#[test]
fn tail_jumps_stating_different_results_are_a_cause_of_that_name() {
    const CODE: [u8; 0x30] = {
        let mut bytes = [0xcc; 0x30];
        let jumps = [
            0x85, 0xff, // 1000 test edi, edi
            0x74, 0x05, // 1002 je 0x1009
            0xe9, 0x0c, 0x00, 0x00, 0x00, // 1004 jmp 0x1015
            0xe9, 0x12, 0x00, 0x00, 0x00, // 1009 jmp 0x1020
        ];
        let g1 = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]; // 1015 mov eax, 1; ret
        let (mut at, mut other) = (0, 0);
        while at < jumps.len() {
            bytes[at] = jumps[at];
            at += 1;
        }
        while other < g1.len() {
            bytes[0x15 + other] = g1[other];
            other += 1;
        }
        bytes[0x20] = 0xc3; // 1020 ret
        bytes
    };
    let functions = [
        ("f", BASE, 0x0e),
        ("g1", BASE + 0x15, 6),
        ("g2", BASE + 0x20, 1),
    ];
    let cause = result_cause(Literal::of_code(&CODE, &functions), BASE);
    assert_eq!(cause, Some(vec![SourceResultCause::TailsDisagree]));
}

/// `ud2`: no return path, and no call that does not come back closes the body.
#[test]
fn a_body_with_no_return_path_is_a_result_of_that_cause() {
    let cause = result_cause(Literal::of_code(&[0x0f, 0x0b], &[("f", BASE, 2)]), BASE);
    assert_eq!(cause, Some(vec![SourceResultCause::NoReturn]));
}

/// `mov eax, 39; syscall; ret`: the kernel leaves `rax` holding a value nothing states.
#[test]
fn a_supervisor_entry_before_the_return_is_a_result_of_that_cause() {
    const CODE: &[u8] = &[0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3];
    let cause = result_cause(Literal::of_code(CODE, &[("f", BASE, 8)]), BASE);
    assert_eq!(cause, Some(vec![SourceResultCause::Clobbered]));
}

/// `xor eax, eax; pxor xmm0, xmm0; ret`: both result registers, and no caller to say which is read.
#[test]
fn a_body_writing_both_result_registers_is_a_result_of_that_cause() {
    const CODE: [u8; 0x30] = beside_both_registers([]);
    let cause = result_cause(Literal::of_code(&CODE, &BOTH), BASE);
    assert_eq!(cause, Some(vec![SourceResultCause::Ambiguous]));
}

/// AArch64 `ret`: `x0` is both the first argument and the result, and the body hands it back.
#[test]
fn an_argument_handed_back_untouched_is_a_result_of_that_cause() {
    const CODE: &[u8] = &[0xc0, 0x03, 0x5f, 0xd6];
    let literal = Literal::of_code(CODE, &[("f", BASE, 4)]).in_aarch64();
    let cause = result_cause(literal, BASE);
    assert_eq!(cause, Some(vec![SourceResultCause::HandedBack]));
}

const AARCH64: [(&str, u64, u64); 3] = [
    ("even", BASE, 0x34),
    ("odd", BASE + 0x34, 0x38),
    ("caller", BASE + 0x70, 0x1c),
];

/// On AArch64 the result and the first argument share `x0`, so the pair is proven only where the
/// paths of its own write it: a residual-free return in each.
#[test]
fn under_aa_an_aarch64_pair_proves_its_result() {
    for (_, at, _) in AARCH64 {
        let mut open = OpenProgram::of(Literal::of_code(MUTUAL_AARCH64, &AARCH64).in_aarch64());
        open.analyse_program().expect("it surveys");
        let text = open
            .rendered(at)
            .expect("it renders")
            .response
            .output
            .into_text();
        assert!(!text.contains("residual"), "{text}");
    }
}
