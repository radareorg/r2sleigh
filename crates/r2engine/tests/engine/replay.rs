//! `pdie`'s replay: the lift run from a recorded entry state.

use crate::common;

use std::collections::BTreeMap;

use common::{BASE, Literal};
use r2engine::program::OpenProgram;
use r2engine::query::replay::{ReplayRequest, ReplayStop, ReplayWrite, replay};

/// mov ecx, 3; loop: inc byte [rdi]; dec ecx; jne loop; ret
const THRICE: &[u8] = &[
    0xb9, 0x03, 0x00, 0x00, 0x00, // 0x1000 mov ecx, 3
    0xfe, 0x07, // 0x1005 inc byte [rdi]
    0xff, 0xc9, // 0x1007 dec ecx
    0x75, 0xfa, // 0x1009 jne 0x1005
    0xc3, // 0x100b ret
];

#[test]
fn an_address_written_three_times_is_one_write_with_its_last_bytes() {
    let program = OpenProgram::of(Literal::of_code(
        THRICE,
        &[("thrice", BASE, THRICE.len() as u64)],
    ));
    let (place, stack) = (0x7000u64, 0x8000u64);
    let mut cells = BTreeMap::from([(place, 0u8)]);
    cells.extend((0..8).map(|at| (stack + at, [0x42, 0x42, 0, 0, 0, 0, 0, 0][at as usize])));
    let request = ReplayRequest {
        entry: BASE,
        bias: 0,
        registers: BTreeMap::from([
            ("RDI".to_owned(), u128::from(place)),
            ("RSP".to_owned(), u128::from(stack)),
        ]),
        cells,
        results: Vec::new(),
    };
    let response = replay(&program, &request).expect("it replays");
    assert_eq!(response.stop, ReplayStop::Returned { to: 0x4242 });
    assert_eq!(
        response.writes,
        [ReplayWrite {
            address: place,
            bytes: vec![3],
        }]
    );
}
