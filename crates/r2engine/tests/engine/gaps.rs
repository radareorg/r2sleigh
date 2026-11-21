//! A listing's gap rows say whether another walked body holds the bytes (D622).

use crate::common;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;

/// `a`: `jmp +1` over `b`'s `ret`, then `jmp +2` over two bytes no body holds, then `ret`.
const CODE: &[u8] = &[
    0xeb, 0x01, // 0x1000 jmp 0x1003
    0xc3, // 0x1002 b: ret
    0xeb, 0x02, // 0x1003 jmp 0x1007
    0xcc, 0xcc, // 0x1005 no body
    0xc3, // 0x1007 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
];

#[test]
fn a_gap_another_body_holds_is_held_and_one_no_body_holds_is_not() {
    let literal = Literal::of_code(CODE, &[("a", BASE, 8), ("b", BASE + 2, 1)]);
    let mut program = OpenProgram::of(literal);
    let listing = program.function_listing(BASE).expect("it lists");
    let gaps = (listing.gaps.iter())
        .map(|gap| (gap.range.clone(), gap.held))
        .collect::<Vec<_>>();
    assert_eq!(
        gaps,
        [(BASE + 2..BASE + 3, true), (BASE + 5..BASE + 7, false)]
    );
}
