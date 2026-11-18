//! A function a body hands to a declared code parameter is read off the walk's own lift (D590).

use crate::common;

use common::{CALLER, GLIBC, Literal, TWO};
use r2engine::discovery::Basis;
use r2engine::program::OpenProgram;

/// `lea rcx, [rip + 9]` (two), `call qword [rip + 0x7b]` (qsort's slot), `ret`: qsort's fourth
/// parameter is its comparator, so two is handed, and no body is sealed to read it.
#[test]
fn a_comparator_handed_to_qsort_is_found_with_no_seal() {
    let mut program = OpenProgram::of(
        Literal::new()
            .stripped_of("two")
            .importing("qsort")
            .running_on(GLIBC),
    );
    program.source_mut().write(
        CALLER,
        &[
            0x48, 0x8d, 0x0d, 0x09, 0, 0, 0, 0xff, 0x15, 0x7b, 0, 0, 0, 0xc3,
        ],
    );
    let found = (program.functions().expect("discovery runs").iter())
        .map(|one| (one.address, one.confidence.basis))
        .collect::<Vec<_>>();
    assert!(found.contains(&(TWO, Basis::Handed)), "{found:x?}");
    assert_eq!(program.analysis_stats().handed_sealed, 0);
}
