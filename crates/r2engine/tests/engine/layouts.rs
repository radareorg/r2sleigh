//! Member names and layouts read the source type graph by type id (ROADMAP D345, D348).

use crate::common;

use common::{BASE, Literal};
use r2abi::{Member, Record, RecordKind, Type, TypeGraph};
use r2engine::program::OpenProgram;

/// `int next_val(struct node *cur) { return cur->next->val; }`.
const NEXT_VAL: &[u8] = &[
    0x48, 0x8b, 0x47, 0x08, // 1000 mov rax, [rdi + 8]
    0x8b, 0x00, // 1004 mov eax, [rax]
    0xc3, // 1006 ret
];

/// `struct node { int val; struct node *next; }` and `int next_val(struct node *cur)`.
fn declaring() -> r2abi::Declarations {
    use r2abi::{Parameter, Prototype, Scalar, ScalarKind, Width};
    let mut graph = TypeGraph::new();
    let int = graph.add(Type::Scalar(Scalar {
        kind: ScalarKind::Signed,
        width: Width::Bits(32),
        name: Some("int".to_owned()),
    }));
    let node = graph.reserve();
    let node_pointer = graph.add(Type::Pointer { target: node });
    let field = |name: &str, ty, at| Member {
        name: Some(name.to_owned()),
        ty,
        offset_bits: at,
        bit_size: None,
    };
    graph.define(
        node,
        Type::Record(Record {
            kind: RecordKind::Struct,
            tag: Some("node".to_owned()),
            size_bytes: 16,
            members: vec![field("val", int, 0), field("next", node_pointer, 64)],
        }),
    );
    let prototype = Prototype {
        name: "next_val".to_owned(),
        parameters: vec![Parameter::new(node_pointer, "struct node *", Some("cur"))],
        returns: "int".into(),
        return_type: int,
        ..Prototype::default()
    };
    let mut declarations = r2abi::Declarations::new(graph);
    declarations.declare_function(BASE, prototype);
    declarations
}

fn program(code: &'static [u8]) -> OpenProgram<Literal> {
    let functions = [("next_val", BASE, code.len() as u64)];
    OpenProgram::of(Literal::of_code(code, &functions).with_declarations(declaring()))
}

/// Each projected access's root slot and member path, in access order.
fn projected(open: &mut OpenProgram<Literal>) -> Vec<String> {
    let prepared = open.prepared(BASE).expect("it prepares");
    let shared = prepared.artifact().shared_artifact();
    let facts = shared.aggregate_accesses();
    let revision = facts.source_revision_identity().expect("a typed interface");
    (facts.projections_for_revision(revision).into_iter())
        .flat_map(|projections| projections.values())
        .map(|projection| projection.member_name.to_string())
        .collect()
}

/// The member a parameter's load reads is named from the projection by type id (D345).
#[test]
fn a_parameter_member_is_named_by_its_projection() {
    let mut open = program(NEXT_VAL);
    assert_eq!(projected(&mut open), ["next"]);
}
