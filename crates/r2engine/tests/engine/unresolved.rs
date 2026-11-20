//! The header's count of indirect transfers no walk followed, from the survey (D619).

use crate::common;

use common::{ONE, TWO, opened};

/// The count `pdf`'s header states for `one` once `two` holds `bytes`.
fn counted(bytes: &[u8]) -> Option<usize> {
    let mut program = opened();
    program.source_mut().write(TWO, bytes);
    program
        .function_listing(ONE)
        .expect("it lists")
        .header
        .unresolved
}

/// `jmp rax`, which no table resolves, may reach any function: one transfer unresolved.
#[test]
fn an_unresolved_indirect_branch_is_counted() {
    assert_eq!(counted(&[0xff, 0xe0]), Some(1));
}

/// `jmp one`, a direct branch, leaves every transfer followed: the list is complete.
#[test]
fn a_direct_branch_leaves_nothing_unresolved() {
    let rel32 = i32::try_from(ONE as i64 - (TWO as i64 + 5)).expect("near");
    let mut jump = vec![0xe9];
    jump.extend_from_slice(&rel32.to_le_bytes());
    assert_eq!(counted(&jump), Some(0));
}

/// `call rax; ret`: an indirect call the walk goes past may call any function.
#[test]
fn an_indirect_call_walked_past_is_counted() {
    assert_eq!(counted(&[0xff, 0xd0, 0xc3]), Some(1));
}
