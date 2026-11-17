//! D570: a call's landing pad is a block of the function, held apart from the normal flow that
//! every analysis reads until D598 states a pad's entry.

use crate::common::{BASE, Literal};
use r2abi::frames::LsdaRead;
use r2engine::program::{EdgeKind, OpenProgram};

const CALLEE: u64 = BASE + 0x20;
const PAD: u64 = BASE + 0x9;

/// `outer`: a call to `callee`, a return, then the call's pad, which reads RAX first.
const UNWINDING: &[u8] = &[
    0xe8, 0x1b, 0x00, 0x00, 0x00, // 0x1000 call 0x1020
    0x83, 0xc0, 0x01, // 0x1005 add eax, 1
    0xc3, // 0x1008 ret
    0x89, 0xc7, // 0x1009 mov edi, eax (the pad)
    0xe8, 0x10, 0x00, 0x00, 0x00, // 0x100b call 0x1020
    0xc3, // 0x1010 ret
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xb8,
    0x07, 0x00, 0x00, 0x00, // 0x1020 mov eax, 7
    0xc3, // 0x1025 ret
];

fn program(lsda: Option<LsdaRead>) -> OpenProgram<Literal> {
    let literal = Literal::of_code(UNWINDING, &[("outer", BASE, 0x11), ("callee", CALLEE, 6)]);
    let gxx = &r2abi::runtime::PERSONALITIES[1];
    let literal = match lsda {
        None => literal,
        Some(LsdaRead::Read(_)) => literal.unwinding_to(
            BASE..BASE + 0x11,
            &[(BASE, BASE + 5, Some(PAD))],
            LsdaRead::Read(gxx),
        ),
        Some(read) => literal.unwinding_to(BASE..BASE + 0x11, &[], read),
    };
    OpenProgram::of(literal)
}

fn read() -> Option<LsdaRead> {
    Some(LsdaRead::Read(&r2abi::runtime::PERSONALITIES[1]))
}

#[test]
fn a_pad_is_a_block_with_an_unwind_edge_and_no_analysis_reads_it() {
    let mut padded = program(read());
    let graph = padded.function_graph(BASE).expect("a graph");
    let starts = graph
        .blocks
        .iter()
        .map(|block| block.address)
        .collect::<Vec<_>>();
    assert_eq!(starts, [BASE, PAD]);
    let call = &graph.blocks[0];
    assert!(
        (call.edges.iter()).any(|edge| (edge.kind, edge.target) == (EdgeKind::Unwind, PAD)),
        "{:#x?}",
        call.edges
    );
    // The prepared function is the normal flow alone.
    let prepared = padded.prepared(BASE).expect("prepared");
    let blocks = (prepared.outline().blocks.iter()).map(|block| block.addr);
    assert_eq!(blocks.collect::<Vec<_>>(), [BASE]);
    let info = padded.function_info(BASE).expect("described");
    assert_eq!(info.blocks.len(), 2);
    assert_eq!(info.edges(), 1);
    let text = (padded.rendered(BASE).expect("it renders").response.output).into_text();
    assert!(
        text.contains("; 1 landing pad not rendered: exceptional flow"),
        "{text}"
    );
}

/// The pad's read of RAX joins no lane of the callee's result: `callee` is described the same.
#[test]
fn a_pad_s_read_of_the_result_register_leaves_the_callee_unchanged() {
    let described = |lsda| {
        let info = program(lsda).function_info(CALLEE).expect("described");
        (info.returns, info.unproven)
    };
    assert_eq!(described(read()), described(None));
}

/// A personality no cited row names states no table: no pad joins the body.
#[test]
fn a_frame_whose_personality_has_no_row_joins_no_pad() {
    let mut unstated = program(Some(LsdaRead::PersonalityUnstated));
    let graph = unstated.function_graph(BASE).expect("a graph");
    let starts = graph
        .blocks
        .iter()
        .map(|block| block.address)
        .collect::<Vec<_>>();
    assert_eq!(starts, [BASE]);
    assert!(graph.blocks[0].edges.is_empty());
}
