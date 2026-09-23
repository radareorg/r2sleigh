//! x86's repeated scans and compares, lifted to the block operations they are.

#![cfg(all(feature = "x86", feature = "sleigh-config"))]

use r2il::{BlockStop, BlockTransferKind, R2ILOp};

/// Every width of `repne scas`, `repe scas`, `repe cmps` and `repne cmps`, with
/// the operation and element size it must lift to.
const FORMS: &[(&[u8], BlockTransferKind, u32)] = &[
    (&[0xf2, 0xae], BlockTransferKind::Scan(BlockStop::Equal), 1),
    (
        &[0x66, 0xf2, 0xaf],
        BlockTransferKind::Scan(BlockStop::Equal),
        2,
    ),
    (&[0xf2, 0xaf], BlockTransferKind::Scan(BlockStop::Equal), 4),
    (
        &[0xf2, 0x48, 0xaf],
        BlockTransferKind::Scan(BlockStop::Equal),
        8,
    ),
    (
        &[0xf3, 0xae],
        BlockTransferKind::Scan(BlockStop::Unequal),
        1,
    ),
    (
        &[0xf3, 0xa6],
        BlockTransferKind::Compare(BlockStop::Unequal),
        1,
    ),
    (
        &[0xf3, 0x66, 0xa7],
        BlockTransferKind::Compare(BlockStop::Unequal),
        2,
    ),
    (
        &[0xf3, 0xa7],
        BlockTransferKind::Compare(BlockStop::Unequal),
        4,
    ),
    (
        &[0xf2, 0x48, 0xa7],
        BlockTransferKind::Compare(BlockStop::Equal),
        8,
    ),
];

#[test]
fn a_repeated_scan_or_compare_lifts_to_one_block_operation() {
    // Sleigh writes each as a loop inside the instruction: a guard, a branch
    // back to its own start, and three reads of the element for its flags.
    // The lift keeps none of that: one operation answers how far it reached
    // and what it compared last, and the flags are computed once from that.
    let machine = r2sleigh_lift::embedded_machine("x86-64").expect("x86-64 machine");
    for (bytes, kind, element) in FORMS {
        let mut padded = bytes.to_vec();
        padded.resize(16, 0);
        let block = machine.disasm.lift(&padded, 0x1000).expect("lifts");
        assert_eq!(block.size as usize, bytes.len(), "{bytes:02x?}");
        let [R2ILOp::BlockTransfer(transfer), ..] = block.ops.as_slice() else {
            panic!("{bytes:02x?}: {:?}", block.ops);
        };
        let (Some(answer), count) = (&transfer.answer, &transfer.count) else {
            panic!("{bytes:02x?}: a scan answers");
        };
        assert_eq!(
            (&transfer.kind, &transfer.element_size),
            (kind, element),
            "{bytes:02x?}"
        );
        let compared = match kind {
            BlockTransferKind::Compare(_) => 2,
            _ => 1,
        };
        assert_eq!(answer.size, count.size + compared * element, "{bytes:02x?}");
        assert!(
            !block.ops.iter().any(|op| matches!(
                op,
                R2ILOp::Unimplemented
                    | R2ILOp::Load { .. }
                    | R2ILOp::LoadGuarded { .. }
                    | R2ILOp::Branch { .. }
                    | R2ILOp::CBranch { .. }
            )),
            "{bytes:02x?}: the element is read once, by the operation: {:?}",
            block.ops
        );
    }
}
