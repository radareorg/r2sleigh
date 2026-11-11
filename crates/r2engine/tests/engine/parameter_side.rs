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

/// The function at `root` rendered after the program is surveyed.
fn surveyed(code: &'static [u8], functions: &[(&str, u64, u64)], root: u64) -> String {
    let mut open = OpenProgram::of(Literal::of_code(code, functions));
    open.analyse_program().expect("it surveys");
    (open.rendered(root).expect("it renders").response.output).into_text()
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
