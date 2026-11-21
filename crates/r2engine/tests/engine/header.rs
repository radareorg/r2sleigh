//! `pdf`'s header from the survey's caller sets: each call and tail branch with its site (D566).

use crate::common;

use common::{CALLER, ONE, PASSES, TWO, opened};

/// `one` is called by `caller` and `passes`, and `two` leaves for it by a tail branch: the header
/// lists 2 calls and 1 tail, each with the instruction that makes it.
#[test]
fn the_header_lists_each_call_and_tail_branch_with_its_site() {
    let mut program = opened();
    // two: jmp one (rel32 = 0x1000 - 0x1025)
    let rel32 = i32::try_from(ONE as i64 - (TWO as i64 + 5)).expect("near");
    let mut jump = vec![0xe9];
    jump.extend_from_slice(&rel32.to_le_bytes());
    program.source_mut().write(TWO, &jump);
    let header = program.function_listing(ONE).expect("it lists").header;
    let calls = header.calls.iter().map(|xref| (xref.from, xref.site));
    assert_eq!(
        calls.collect::<Vec<_>>(),
        [(CALLER, CALLER), (PASSES, PASSES + 7)]
    );
    let tails = header.tails.iter().map(|xref| (xref.from, xref.site));
    assert_eq!(tails.collect::<Vec<_>>(), [(TWO, TWO)]);
    assert!(header.info.is_some(), "the seal states the frame answer");
}
