//! A function's body is bounded by where other functions begin, and only there.

use crate::common;

use common::{BASE, CALLER, Literal, TWO, opened};
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
    // An import's undefined symbol and a data label at the branch target each
    // say no function begins there.
    let stray = |name: &str, kind, defined| Symbol {
        name: name.into(),
        vaddr: TWO + 0xa,
        size: 0,
        kind,
        defined,
        thumb: false,
        ..Symbol::default()
    };
    for literal in [
        Literal::new(),
        Literal::new().declaring(stray("imported", SymbolKind::Function, false)),
        Literal::new().declaring(stray("label", SymbolKind::Data, true)),
    ] {
        assert_eq!(
            listed_after_branch(OpenProgram::of(literal)),
            [0x0, 0x2, 0x4, 0x9, 0xa, 0xf]
        );
    }
    // A defined function symbol states a function by its kind, named or not, as `afl` seeds it.
    let nameless = Literal::new().declaring(stray("", SymbolKind::Function, true));
    assert_eq!(
        listed_after_branch(OpenProgram::of(nameless)),
        [0x0, 0x2, 0x4, 0x9]
    );
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

/// `count` from wc at -O2: the `cmp cl, 0xd` / `cmp cl, 0x20` chain the analysis fuses into one
/// block, which the walk keeps as two.
const COUNT: &[u8] = &[
    0x48, 0x85, 0xf6, 0x0f, 0x84, 0x82, 0x00, 0x00, 0x00, 0x48, 0x89, 0xf8, 0x48, 0x01, 0xf7, 0x41,
    0xb8, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x41, 0xb9, 0x00, 0x00, 0x00, 0x00,
    0x41, 0xba, 0x01, 0x00, 0x00, 0x00, 0xeb, 0x15, 0x80, 0xf9, 0x09, 0x75, 0x29, 0x48, 0x83, 0xc6,
    0x01, 0x45, 0x89, 0xc8, 0x48, 0x83, 0xc0, 0x01, 0x48, 0x39, 0xf8, 0x74, 0x4e, 0x48, 0x83, 0x42,
    0x10, 0x01, 0x0f, 0xb6, 0x08, 0x80, 0xf9, 0x0a, 0x74, 0x1f, 0x7e, 0xdc, 0x80, 0xf9, 0x0d, 0x74,
    0xdc, 0x80, 0xf9, 0x20, 0x74, 0xd7, 0x48, 0x83, 0xc6, 0x01, 0x45, 0x85, 0xc0, 0x75, 0xd5, 0x48,
    0x83, 0x42, 0x08, 0x01, 0x45, 0x89, 0xd0, 0xeb, 0xcb, 0x48, 0x83, 0x02, 0x01, 0x48, 0x39, 0x72,
    0x18, 0x7d, 0x0e, 0x48, 0x89, 0x72, 0x18, 0x45, 0x89, 0xc8, 0xbe, 0x00, 0x00, 0x00, 0x00, 0xeb,
    0xb3, 0x45, 0x89, 0xc8, 0xbe, 0x00, 0x00, 0x00, 0x00, 0xeb, 0xa9, 0xc3,
];

#[test]
fn afi_counts_the_blocks_afb_lists_after_a_compare_chain_is_fused() {
    let mut program = OpenProgram::of(Literal::of_code(
        COUNT,
        &[("count", BASE, COUNT.len() as u64)],
    ));
    let graph = program.function_graph(BASE).expect("it graphs");
    let info = program.function_info(BASE).expect("it is described");
    assert!(info.refused.is_none());
    let graphed = (graph.blocks.iter())
        .map(|block| {
            (
                block.address,
                block.size,
                block.lines.len(),
                block.edges.len(),
            )
        })
        .collect::<Vec<_>>();
    let described = (info.blocks.iter())
        .map(|block| (block.addr, block.size, block.instructions, block.successors))
        .collect::<Vec<_>>();
    assert_eq!(described, graphed);
    // radare2 6.2.5's `afi`: 15 blocks, 23 edges, 42 instructions.
    assert_eq!(
        (info.blocks.len(), info.edges(), info.instructions()),
        (15, 23, 42)
    );
}
