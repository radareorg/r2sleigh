//! The parameter side denies by default: an upper bound on what a body reads needs an owner that
//! states completeness (doc/adr-result-side.md, "Parameter side"; ROADMAP D326 to D329).

use crate::common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;
use r2ssa::body_boundary::SlotUse;
use r2ssa::{SourceFloorCause, SourceUnprovenCall};

/// `code` at `BASE`, padded with `int3` to `M` bytes.
const fn padded<const N: usize, const M: usize>(code: [u8; N]) -> [u8; M] {
    let mut bytes = [0xcc; M];
    let mut at = 0;
    while at < N {
        bytes[at] = code[at];
        at += 1;
    }
    bytes
}

/// The causes the function at `BASE` states its arity a floor for; none where it is exact.
fn floor_causes(literal: Literal) -> Vec<SourceFloorCause> {
    let mut open = OpenProgram::of(literal);
    let prepared = open.prepared(BASE).expect("it prepares");
    let shared = prepared.artifact().shared_artifact();
    let interface = (shared.machine_context().function_interface()).expect("an interface");
    (interface.arity_floor()).map_or_else(Vec::new, |floor| floor.causes().to_vec())
}

/// Each slot's use as the body at `BASE` states it.
fn slot_uses(literal: Literal) -> Vec<SlotUse> {
    let mut open = OpenProgram::of(literal);
    let prepared = open.prepared(BASE).expect("it prepares");
    let shared = prepared.artifact().shared_artifact();
    let boundary = (shared.facts().body_boundary.as_ref()).expect("a recovered body states it");
    boundary
        .slots
        .iter()
        .map(|(_, used)| used.clone())
        .collect()
}

/// The six integer registers written, `xmm0` stored, then a call through memory the program may
/// write: the callee states nothing, and `xmm1` reaches it as the function was entered with it.
const SIX_WRITTEN_THEN_THROUGH_MEMORY: [u8; 0x50] = padded([
    0xbf, 0x01, 0x00, 0x00, 0x00, // 1000 mov edi, 1
    0xbe, 0x02, 0x00, 0x00, 0x00, // 1005 mov esi, 2
    0xba, 0x03, 0x00, 0x00, 0x00, // 100a mov edx, 3
    0xb9, 0x04, 0x00, 0x00, 0x00, // 100f mov ecx, 4
    0x41, 0xb8, 0x05, 0x00, 0x00, 0x00, // 1014 mov r8d, 5
    0x41, 0xb9, 0x06, 0x00, 0x00, 0x00, // 101a mov r9d, 6
    0xf2, 0x0f, 0x11, 0x05, 0x20, 0x00, 0x00, 0x00, // 1020 movsd [rip + 0x20], xmm0
    0xff, 0x15, 0x12, 0x00, 0x00, 0x00, // 1028 call [rip + 0x12]
    0xc3, // 102e ret
]);

/// The registers a caller wrote are no statement of its callee's arity: a call nothing states may
/// read the next float register, so the float parameters are a floor (finding 11).
#[test]
fn six_written_registers_do_not_prove_the_arity_of_a_call_nothing_states() {
    let literal = Literal::of_code(&SIX_WRITTEN_THEN_THROUGH_MEMORY, &[("f", BASE, 0x2f)])
        .writable_data_after(BASE + 0x40);
    assert_eq!(
        floor_causes(literal),
        [SourceFloorCause::HandedOn(SourceUnprovenCall::Indirect)]
    );
}

/// `mov edx, edi; mov eax, esi; out dx, al; xor eax, eax; xor edx, edx; ret`: a port write the
/// lift models as a user operation, whose inputs are the two entry registers and reach no return.
const PORT_WRITE: &[u8] = &[
    0x89, 0xfa, // 1000 mov edx, edi
    0x89, 0xf0, // 1002 mov eax, esi
    0xee, // 1004 out dx, al
    0x31, 0xc0, // 1005 xor eax, eax
    0x31, 0xd2, // 1007 xor edx, edx
    0xc3, // 1009 ret
];

/// An entry value only an unmodelled operation reads is not proven dead, so its slot is no
/// `Unread`: the use is unknown and the arity a floor (finding 2).
#[test]
fn an_entry_value_only_an_unmodelled_operation_reads_is_unknown_not_unread() {
    let literal = || Literal::of_code(PORT_WRITE, &[("f", BASE, 10)]);
    let uses = slot_uses(literal());
    assert_eq!(
        uses[..2],
        [
            SlotUse::Unknown(SourceFloorCause::RegisterRead),
            SlotUse::Unknown(SourceFloorCause::RegisterRead)
        ],
        "{uses:?}"
    );
    assert_eq!(floor_causes(literal()), [SourceFloorCause::RegisterRead]);
}

/// `xor edx, edx; mov eax, edi; ret`: `rdx` is read only by an operation that folds it away, and
/// `rsi` by nothing, so both are proven dead and the arity is exact.
#[test]
fn an_entry_value_proven_dead_is_unread_and_the_arity_exact() {
    const CODE: &[u8] = &[0x31, 0xd2, 0x89, 0xf8, 0xc3];
    let literal = || Literal::of_code(CODE, &[("f", BASE, 5)]);
    let uses = slot_uses(literal());
    assert!(matches!(uses[0], SlotUse::Read { .. }), "{uses:?}");
    assert_eq!(uses[1..3], [SlotUse::Unread, SlotUse::Unread], "{uses:?}");
    assert_eq!(floor_causes(literal()), []);
}

/// The six integer registers summed, then `add rax, [rsp + 0xc]`: eight bytes that start in the
/// first argument-area slot and end in the second.
const CROSSING_READ: &[u8] = &[
    0x48, 0x89, 0xf8, // 1000 mov rax, rdi
    0x48, 0x01, 0xf0, // 1003 add rax, rsi
    0x48, 0x01, 0xd0, // 1006 add rax, rdx
    0x48, 0x01, 0xc8, // 1009 add rax, rcx
    0x4c, 0x01, 0xc0, // 100c add rax, r8
    0x4c, 0x01, 0xc8, // 100f add rax, r9
    0x48, 0x03, 0x44, 0x24, 0x0c, // 1012 add rax, [rsp + 0xc]
    0xc3, // 1017 ret
];

/// A read crossing two argument-area slots places no parameter and bounds none: behind a full
/// register section the arity is a floor, never exact at six (finding 8).
#[test]
fn a_read_crossing_two_argument_area_slots_is_a_floor() {
    let literal = Literal::of_code(CROSSING_READ, &[("f", BASE, 0x18)]);
    assert_eq!(floor_causes(literal), [SourceFloorCause::ArgumentAreaRead]);
}

/// The six registers summed, then `add rax, [rsp + rdi*8 + 8]`: a read of the argument area at an
/// index no rule bounds.
const INDEXED_READ: &[u8] = &[
    0x48, 0x89, 0xf8, // 1000 mov rax, rdi
    0x48, 0x01, 0xf0, // 1003 add rax, rsi
    0x48, 0x01, 0xd0, // 1006 add rax, rdx
    0x48, 0x01, 0xc8, // 1009 add rax, rcx
    0x4c, 0x01, 0xc0, // 100c add rax, r8
    0x4c, 0x01, 0xc8, // 100f add rax, r9
    0x48, 0x03, 0x44, 0xfc, 0x08, // 1012 add rax, [rsp + rdi*8 + 8]
    0xc3, // 1017 ret
];

/// A read of the argument area whose place is unproven bounds no parameter count (finding 8).
#[test]
fn a_read_of_the_argument_area_at_an_unproven_place_is_a_floor() {
    let literal = Literal::of_code(INDEXED_READ, &[("f", BASE, 0x18)]);
    assert_eq!(floor_causes(literal), [SourceFloorCause::ArgumentAreaRead]);
}

/// The same six, then `add rax, [rsp + 8]`: one whole slot, read in place, is the seventh
/// parameter and the arity exact.
#[test]
fn a_whole_slot_read_in_place_is_a_parameter_and_no_floor() {
    const CODE: &[u8] = &[
        0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0x48, 0x01, 0xd0, 0x48, 0x01, 0xc8, 0x4c, 0x01, 0xc0,
        0x4c, 0x01, 0xc8, // 1000 the six summed
        0x48, 0x03, 0x44, 0x24, 0x08, // 1012 add rax, [rsp + 8]
        0xc3, // 1017 ret
    ];
    let literal = Literal::of_code(CODE, &[("f", BASE, 0x18)]);
    assert_eq!(floor_causes(literal), []);
}
