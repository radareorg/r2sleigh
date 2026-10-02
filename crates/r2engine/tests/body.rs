//! A function's body is bounded by where other functions begin, and only there.

mod common;

use common::{CALLER, Literal, TWO, opened};
use r2engine::program::{EdgeKind, OpenProgram, Symbol, SymbolKind};

/// What `two` lists once it branches within itself, as offsets into it.
fn listed_after_branch(mut program: OpenProgram<Literal>) -> Vec<u64> {
    // test edi, edi; je +6; mov eax, 2; ret; mov eax, 3; ret
    program.source_mut().write(
        TWO,
        &[
            0x85, 0xff, 0x74, 0x06, 0xb8, 0x02, 0, 0, 0, 0xc3, 0xb8, 0x03, 0, 0, 0, 0xc3,
        ],
    );
    program
        .function_listing(TWO)
        .expect("it lists")
        .lines
        .value
        .iter()
        .map(|line| line.address - TWO)
        .collect()
}

#[test]
fn a_branch_inside_a_function_stays_inside_it() {
    // An import's undefined symbol, a nameless one and a data label at the
    // branch target each say no function begins there.
    let stray = |name: &str, kind, defined| Symbol {
        name: name.to_owned(),
        vaddr: TWO + 0xa,
        size: 0,
        kind,
        defined,
        thumb: false,
    };
    for literal in [
        Literal::new(),
        Literal::new().declaring(stray("imported", SymbolKind::Function, false)),
        Literal::new().declaring(stray("", SymbolKind::Function, true)),
        Literal::new().declaring(stray("label", SymbolKind::Data, true)),
    ] {
        assert_eq!(
            listed_after_branch(OpenProgram::of(literal)),
            [0x0, 0x2, 0x4, 0x9, 0xa, 0xf]
        );
    }
}

/// What `caller` lists once it ends in `jmp` to `rel32`, as offsets into it.
fn listed_after_tail_jump(mut program: OpenProgram<Literal>, rel32: i32) -> Vec<u64> {
    let mut jump = vec![0xe9];
    jump.extend_from_slice(&rel32.to_le_bytes());
    program.source_mut().write(CALLER, &jump);
    program
        .function_listing(CALLER)
        .expect("it lists")
        .lines
        .value
        .iter()
        .map(|line| line.address - CALLER)
        .collect()
}

#[test]
fn a_jump_to_another_function_leaves_the_body() {
    // To `one`, which the container states, and to the stub the loader's
    // table places; neither body is this function's.
    assert_eq!(listed_after_tail_jump(opened(), -0x15), [0x0]);
    assert_eq!(
        listed_after_tail_jump(OpenProgram::of(Literal::new().importing("puts")), 0x7b),
        [0x0]
    );
}

#[test]
fn a_function_graph_is_its_blocks_and_where_each_one_leaves() {
    // test edi, edi; je +6; mov eax, 2; ret; mov eax, 3; ret
    let mut program = opened();
    program.source_mut().write(
        TWO,
        &[
            0x85, 0xff, 0x74, 0x06, 0xb8, 0x02, 0, 0, 0, 0xc3, 0xb8, 0x03, 0, 0, 0, 0xc3,
        ],
    );
    let graph = program.function_graph(TWO).expect("it graphs");
    assert!(graph.refused.is_none());
    let shape = graph
        .blocks
        .iter()
        .map(|block| {
            let lines = block
                .lines
                .iter()
                .map(|line| line.address - TWO)
                .collect::<Vec<_>>();
            let edges = block
                .edges
                .iter()
                .map(|edge| (edge.target - TWO, edge.kind))
                .collect::<Vec<_>>();
            (block.address - TWO, block.size, lines, edges)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        shape,
        [
            (
                0x0,
                4,
                vec![0x0, 0x2],
                vec![(0xa, EdgeKind::Taken), (0x4, EdgeKind::NotTaken)]
            ),
            (0x4, 6, vec![0x4, 0x9], vec![]),
            (0xa, 6, vec![0xa, 0xf], vec![]),
        ]
    );
    // Every line the listing has is in exactly one block.
    let listed = program.function_listing(TWO).expect("it lists").lines.value;
    let graphed = graph.blocks.iter().flat_map(|block| &block.lines);
    assert!(listed.iter().eq(graphed));

    // A jump to another function is that function's, not an edge.
    let mut program = opened();
    let mut jump = vec![0xe9];
    jump.extend_from_slice(&(-0x15_i32).to_le_bytes());
    program.source_mut().write(CALLER, &jump);
    let graph = program.function_graph(CALLER).expect("it graphs");
    assert_eq!(graph.blocks.len(), 1);
    assert!(graph.blocks[0].edges.is_empty());
}
