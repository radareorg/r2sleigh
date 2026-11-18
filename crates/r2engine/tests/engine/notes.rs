//! What a listing's notes stand on: a refusal is a kind with its reason, never a fact (D579).

use crate::common;
use common::{BASE, GLIBC, Literal, PLT_CALLER};
use r2engine::discovery::Basis;
use r2engine::program::OpenProgram;
use r2engine::query::{
    AnnotationKind, CallBoundaryRefusal, Confidence, Fact, Line, Mark, ResultStanding, Standing,
    UnstatedImport,
};

/// bomb `phase_3`'s call after `.plt`: `sscanf(input, "%d %d", &a, &b)` to an import no table
/// declares, so its boundary refuses the arguments.
const PHASE_3: [u8; 0x48] = common::plt_then(&[
    0x48, 0x83, 0xec, 0x18, // 1020 sub rsp, 0x18
    0x48, 0x8d, 0x4c, 0x24, 0x0c, // 1024 lea rcx, [rsp + 0xc]
    0x48, 0x8d, 0x54, 0x24, 0x08, // 1029 lea rdx, [rsp + 8]
    0xbe, 0x42, 0x10, 0x00, 0x00, // 102e mov esi, 0x1042
    0xb8, 0x00, 0x00, 0x00, 0x00, // 1033 mov eax, 0
    0xe8, 0xd3, 0xff, 0xff, 0xff, // 1038 call stub
    0x48, 0x83, 0xc4, 0x18, // 103d add rsp, 0x18
    0xc3, // 1041 ret
    b'%', b'd', b' ', b'%', b'd', 0x00, // 1042 the format
]);

fn listed() -> Vec<Line> {
    let literal = Literal::plt_wrapped("__isoc99_sscanf", &PHASE_3);
    let listing = OpenProgram::of(literal).function_listing(PLT_CALLER);
    listing.expect("it lists").lines.value
}

#[test]
fn a_refused_call_is_a_refusal_with_its_reason_and_marks_so() {
    let lines = listed();
    let call = (lines.iter().find(|line| line.address == PLT_CALLER + 0x18)).expect("the call");
    let note = (call.annotations.iter())
        .find(|annotation| matches!(annotation.kind, AnnotationKind::Call { .. }))
        .expect("the call's note");
    let AnnotationKind::Call { ref arguments, .. } = note.kind else {
        unreachable!();
    };
    let undeclared = CallBoundaryRefusal::ImportUnstated(UnstatedImport::Undeclared);
    assert_eq!(arguments, &Err(undeclared), "{note:?}");
    assert_eq!(note.kind.standing(), Standing::Refused);
    assert_eq!(note.mark(), Mark::Refused);
    assert_eq!(
        undeclared.to_string(),
        "the import has no declaration to state its arguments"
    );
}

#[test]
fn every_refusal_and_unknown_kind_stands_below_a_fact() {
    let refusals = [
        CallBoundaryRefusal::NoConvention,
        CallBoundaryRefusal::ImportUnstated(UnstatedImport::Undeclared),
    ];
    for why in refusals {
        let call = AnnotationKind::Call {
            callee: None,
            arguments: Err(why),
            noreturn: None,
        };
        assert_eq!(call.standing(), Standing::Refused);
    }
    assert_eq!(AnnotationKind::Unresolved.standing(), Standing::Unknown);
    // A `ret` whose result `afi` calls unproven is refused with its cause, never a fact (D584).
    let unproven = AnnotationKind::Returns {
        storage: None,
        standing: ResultStanding::Unproven(Some(r2types::UnprovenCause::Written)),
    };
    assert_eq!(unproven.standing(), Standing::Refused);
    let proven = AnnotationKind::Call {
        callee: None,
        arguments: Ok(Vec::new()),
        noreturn: None,
    };
    assert_eq!(proven.standing(), Standing::Fact);
    // Every note the listing prints is a fact, a refusal or an unknown, and its mark says which.
    for annotation in listed().iter().flat_map(|line| &line.annotations) {
        let mark = annotation.mark();
        match annotation.kind.standing() {
            Standing::Fact => assert!(!matches!(mark, Mark::Refused | Mark::Unknown)),
            Standing::Refused => assert_eq!(mark, Mark::Refused),
            Standing::Unknown => assert_eq!(mark, Mark::Unknown),
        }
    }
}

/// `caller: call exit; ret`, then `exit`'s stub at [`common::STUB`].
fn calling_exit() -> &'static [u8] {
    let mut code = vec![0xcc; 0xa0];
    let call = (common::STUB - (BASE + 5)) as u32;
    code[0] = 0xe8;
    code[1..5].copy_from_slice(&call.to_le_bytes());
    code[5] = 0xc3;
    code[0x90..0x96].copy_from_slice(&common::JUMP_STUB);
    code[0x98..0xa0].fill(0);
    Box::leak(code.into_boxed_slice())
}

/// A call's noreturn is the callee's own `Never`, here `exit`'s cited row: a declaration found by
/// the import's name, so the note stands on `declared` and no name decides it.
#[test]
fn a_call_to_a_cited_noreturn_states_it_on_the_callee_s_never() {
    let literal = Literal::of_code(calling_exit(), &[("caller", BASE, 6)])
        .importing("exit")
        .running_on(GLIBC);
    let listing = OpenProgram::of(literal).function_listing(BASE);
    let lines = listing.expect("it lists").lines.value;
    let call = (lines.iter().find(|line| line.address == BASE)).expect("the call");
    let noreturn = (call.annotations.iter()).find_map(|annotation| match &annotation.kind {
        AnnotationKind::Call { noreturn, .. } => Some(noreturn.clone()),
        _ => None,
    });
    let declared = Fact::new(true, Confidence::of(Basis::Declared));
    assert_eq!(noreturn, Some(Some(declared)), "{call:?}");
}
