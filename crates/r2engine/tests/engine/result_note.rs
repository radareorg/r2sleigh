//! A `ret` line's result note and `afi` read one owner, r2types' sealed return fact (D584).

use crate::common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;
use r2engine::query::{AnnotationKind, ResultStanding};

/// `f`: `test edi, edi; je L; mov eax, 7; L: ret`, which nothing calls: a written result no read
/// decides.
const WRITTEN: &[u8] = &[
    0x85, 0xff, // 1000 test edi, edi
    0x74, 0x05, // 1002 je 0x1009
    0xb8, 0x07, 0x00, 0x00, 0x00, // 1004 mov eax, 7
    0xc3, // 1009 ret
];

#[test]
fn a_ret_note_states_the_unproven_result_afi_names() {
    let mut open = OpenProgram::of(Literal::of_code(WRITTEN, &[("f", BASE, 0x0a)]));
    let unproven = open.function_info(BASE).expect("it is described").unproven;
    let unproven = unproven.expect("afi states an unproven result");
    let listing = open.function_listing(BASE).expect("it lists");
    let ret = listing
        .lines
        .value
        .iter()
        .find(|line| line.address == BASE + 9);
    let notes = ret.expect("the ret is listed").annotations.iter();
    let returns = notes.filter_map(|note| match &note.kind {
        AnnotationKind::Returns { storage, standing } => Some((*storage, standing.clone())),
        _ => None,
    });
    let returns = returns.collect::<Vec<_>>();
    assert_eq!(
        returns,
        [(unproven.carrier, ResultStanding::Unproven(unproven.cause))]
    );
    assert_eq!(unproven.cause_name(), "Written");
}
