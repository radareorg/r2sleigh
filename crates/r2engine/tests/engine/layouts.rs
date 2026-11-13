//! Member names and layouts read the source type graph by type id (ROADMAP D345, D348).

use crate::common;

use common::{BASE, Literal};
use r2abi::{Member, Record, RecordKind, Signature, StatedConvention, Type, TypeGraph, TypeId};
use r2engine::program::{OpenProgram, Symbol, SymbolKind};

/// `int next_val(struct node *cur) { return cur->next->val; }`.
const NEXT_VAL: &[u8] = &[
    0x48, 0x8b, 0x47, 0x08, // 1000 mov rax, [rdi + 8]
    0x8b, 0x00, // 1004 mov eax, [rax]
    0xc3, // 1006 ret
];

/// `void use(struct holder *h) { h->ops->f(h->ops->o, h->ops->o); }`.
const LOADED_MEMBER_CALL: &[u8] = &[
    0x48, 0x83, 0xec, 0x08, // 1000 sub rsp, 8
    0x48, 0x8b, 0x07, // 1004 mov rax, [rdi]
    0x48, 0x8b, 0x48, 0x08, // 1007 mov rcx, [rax + 8]
    0x48, 0x8b, 0x38, // 100b mov rdi, [rax]
    0x48, 0x89, 0xfe, // 100e mov rsi, rdi
    0xff, 0xd1, // 1011 call rcx
    0x48, 0x83, 0xc4, 0x08, // 1013 add rsp, 8
    0xc3, // 1017 ret
];

/// `void use(void *p) { struct ops o; o.o = p; o.f(o.o, o.o); }`, `o` at the frame's bottom.
const FRAME_MEMBER_CALL: &[u8] = &[
    0x48, 0x83, 0xec, 0x18, // 1000 sub rsp, 0x18
    0x48, 0x89, 0x3c, 0x24, // 1004 mov [rsp], rdi
    0x48, 0x8b, 0x44, 0x24, 0x08, // 1008 mov rax, [rsp + 8]
    0x48, 0x8b, 0x3c, 0x24, // 100d mov rdi, [rsp]
    0x48, 0x89, 0xfe, // 1011 mov rsi, rdi
    0xff, 0xd0, // 1014 call rax
    0x48, 0x83, 0xc4, 0x18, // 1016 add rsp, 0x18
    0xc3, // 101a ret
];

/// `int last(struct node *p) { while (p->next) p = p->next; return p->val; }`: `p` merges the
/// parameter with a load.
const WALKED: &[u8] = &[
    0x48, 0x8b, 0x47, 0x08, // 1000 mov rax, [rdi + 8]
    0x48, 0x85, 0xc0, // 1004 test rax, rax
    0x74, 0x05, // 1007 je 0x100e
    0x48, 0x89, 0xc7, // 1009 mov rdi, rax
    0xeb, 0xf2, // 100c jmp 0x1000
    0x8b, 0x07, // 100e mov eax, [rdi]
    0xc3, // 1010 ret
];

/// `cur->next` then a 2-byte read of the 4-byte `val`: no member is that read.
const NARROW_VAL: &[u8] = &[
    0x48, 0x8b, 0x47, 0x08, // 1000 mov rax, [rdi + 8]
    0x0f, 0xb7, 0x00, // 1004 movzx eax, word [rax]
    0xc3, // 1007 ret
];

/// `h->ops->o` then a read 8 bytes into what `o` points at: `void *` names no struct.
const THROUGH_VOID: &[u8] = &[
    0x48, 0x8b, 0x07, // 1000 mov rax, [rdi]
    0x48, 0x8b, 0x00, // 1003 mov rax, [rax]
    0x8b, 0x40, 0x08, // 1006 mov eax, [rax + 8]
    0xc3, // 1009 ret
];

/// Where `GLOBAL_MEMBER_CALL`'s `g_ops` lies, after its code.
const G_OPS: u64 = BASE + 0x20;

/// `void use(void) { g_ops.f(g_ops.o, g_ops.o); }`, then `g_ops`'s 16 bytes.
const GLOBAL_MEMBER_CALL: &[u8] = &[
    0x48, 0x83, 0xec, 0x08, // 1000 sub rsp, 8
    0x48, 0x8b, 0x3c, 0x25, 0x20, 0x10, 0x00, 0x00, // 1004 mov rdi, [0x1020]
    0x48, 0x8b, 0x04, 0x25, 0x28, 0x10, 0x00, 0x00, // 100c mov rax, [0x1028]
    0x48, 0x89, 0xfe, // 1014 mov rsi, rdi
    0xff, 0xd0, // 1017 call rax
    0x48, 0x83, 0xc4, 0x08, // 1019 add rsp, 8
    0xc3, // 101d ret
    0x90, 0x90, // 101e
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 1020 g_ops
];

/// The declared types: `struct node`, `struct ops { void *o; void (*f)(void *, void *); }` and
/// `struct holder { struct ops *ops; }`.
struct Types {
    graph: TypeGraph,
    int: TypeId,
    node_pointer: TypeId,
    ops: TypeId,
    holder_pointer: TypeId,
}

fn types() -> Types {
    use r2abi::{Scalar, ScalarKind, Width};
    let mut graph = TypeGraph::new();
    let field = |name: &str, ty, at| Member {
        name: Some(name.to_owned()),
        ty,
        offset_bits: at,
        bit_size: None,
    };
    let int = graph.add(Type::Scalar(Scalar {
        kind: ScalarKind::Signed,
        width: Width::Bits(32),
        name: Some("int".to_owned()),
    }));
    let node = graph.reserve();
    let node_pointer = graph.add(Type::Pointer { target: node });
    graph.define(
        node,
        Type::Record(Record {
            kind: RecordKind::Struct,
            tag: Some("node".to_owned()),
            size_bytes: 16,
            members: vec![field("val", int, 0), field("next", node_pointer, 64)],
        }),
    );
    let void_pointer = graph.add(Type::Pointer {
        target: TypeId::VOID,
    });
    let code = graph.add(Type::Code(Signature {
        returns: TypeId::VOID,
        parameters: vec![void_pointer; 2],
        variadic: false,
        prototyped: true,
        convention: StatedConvention::Normal,
    }));
    let function_pointer = graph.add(Type::Pointer { target: code });
    let ops = graph.add(Type::Record(Record {
        kind: RecordKind::Struct,
        tag: Some("ops".to_owned()),
        size_bytes: 16,
        members: vec![
            field("o", void_pointer, 0),
            field("f", function_pointer, 64),
        ],
    }));
    let ops_pointer = graph.add(Type::Pointer { target: ops });
    let holder = graph.add(Type::Record(Record {
        kind: RecordKind::Struct,
        tag: Some("holder".to_owned()),
        size_bytes: 8,
        members: vec![field("ops", ops_pointer, 0)],
    }));
    let holder_pointer = graph.add(Type::Pointer { target: holder });
    Types {
        graph,
        int,
        node_pointer,
        ops,
        holder_pointer,
    }
}

/// A function at `BASE` declared to take one parameter of `parameter` and return `returns`.
fn declaring(
    name: &str,
    parameter: Option<(TypeId, &str)>,
    returns: TypeId,
) -> r2abi::Declarations {
    use r2abi::{Parameter, Prototype};
    let types = types();
    let prototype = Prototype {
        name: name.to_owned(),
        parameters: (parameter.into_iter())
            .map(|(ty, spelled)| Parameter::new(ty, spelled, Some("p")))
            .collect(),
        returns: if returns == TypeId::VOID {
            "void"
        } else {
            "int"
        }
        .into(),
        return_type: returns,
        ..Prototype::default()
    };
    let mut declarations = r2abi::Declarations::new(types.graph);
    declarations.declare_function(BASE, prototype);
    declarations
}

fn program(code: &'static [u8], declarations: r2abi::Declarations) -> OpenProgram<Literal> {
    let functions = [("f", BASE, code.len() as u64)];
    OpenProgram::of(Literal::of_code(code, &functions).with_declarations(declarations))
}

/// Each projected access's member path and root kind, in access order.
fn projected(open: &mut OpenProgram<Literal>) -> Vec<(String, &'static str)> {
    let prepared = open.prepared(BASE).expect("it prepares");
    let shared = prepared.artifact().shared_artifact();
    let facts = shared.aggregate_accesses();
    let revision = facts.source_revision_identity().expect("a typed interface");
    (facts.projections_for_revision(revision).into_iter())
        .flat_map(|projections| projections.values())
        .map(|projection| {
            let root = match projection.root {
                r2ssa::AggregateRoot::Parameter(_) => "parameter",
                r2ssa::AggregateRoot::FrameSlot(_) => "frame",
                r2ssa::AggregateRoot::DataObject { .. } => "data",
                r2ssa::AggregateRoot::Member(_) => "member",
            };
            (projection.member_name.to_string(), root)
        })
        .collect()
}

/// The one call's member row and whether its argument count is proven.
fn member_call(open: &mut OpenProgram<Literal>) -> (bool, usize, bool) {
    let prepared = open.prepared(BASE).expect("it prepares");
    let shared = prepared.artifact().shared_artifact();
    let (&site, _) = (shared.facts().call_sites.by_id.iter().next()).expect("one call");
    let boundary = &shared.facts().boundaries.calls[&site];
    let row = matches!(shared.member_calls().get(site), Some(Ok(_)));
    (row, boundary.arguments.len(), boundary.arguments_proven)
}

/// D345: the member a parameter's load reads is named from the projection by type id. D348: the
/// struct a projected pointer member points at roots the next load.
#[test]
fn a_loaded_pointer_member_roots_the_next_projection() {
    let types = types();
    let mut open = program(
        NEXT_VAL,
        declaring(
            "next_val",
            Some((types.node_pointer, "struct node *")),
            types.int,
        ),
    );
    assert_eq!(
        projected(&mut open),
        [
            ("next".to_string(), "parameter"),
            ("val".to_string(), "member")
        ]
    );
}

/// D348 gate 7: `h->ops->f(...)` takes the member's two declared parameters.
#[test]
fn a_call_through_a_loaded_members_member_takes_its_type_as_contract() {
    let types = types();
    let declarations = declaring(
        "use",
        Some((types.holder_pointer, "struct holder *")),
        TypeId::VOID,
    );
    let mut open = program(LOADED_MEMBER_CALL, declarations);
    let roots = projected(&mut open);
    assert!(roots.contains(&("f".to_string(), "member")), "{roots:?}");
    assert_eq!(member_call(&mut open), (true, 2, true));
}

/// D348 gate 7: `g_ops.f(...)`, a member of a struct-typed global, takes its type as contract.
#[test]
fn a_call_through_a_global_structs_member_takes_its_type_as_contract() {
    let types = types();
    let mut declarations = declaring("use", None, TypeId::VOID);
    declarations.declare_object(
        G_OPS,
        r2abi::DataObject {
            name: "g_ops".to_owned(),
            ty: types.ops,
            size_bytes: Some(16),
        },
    );
    let functions = [("use", BASE, 0x1e)];
    let literal = Literal::of_code(GLOBAL_MEMBER_CALL, &functions)
        .writable_data_after(G_OPS)
        .declaring(Symbol {
            name: "g_ops".into(),
            vaddr: G_OPS,
            size: 16,
            kind: SymbolKind::Data,
            defined: true,
            ..Symbol::default()
        })
        .with_declarations(declarations);
    let mut open = OpenProgram::of(literal);
    let roots = projected(&mut open);
    assert!(roots.contains(&("f".to_string(), "data")), "{roots:?}");
    assert_eq!(member_call(&mut open), (true, 2, true));
    let text = (open.rendered(BASE).expect("it renders").response.output).into_text();
    assert!(!text.contains("r2dec gap"), "{text}");
}

/// D348 gate 7: `o.f(...)`, a member of a struct the frame declares by value.
#[test]
fn a_call_through_a_frame_structs_member_takes_its_type_as_contract() {
    use r2abi::{FrameBase, Local, Parameter, Prototype};
    let types = types();
    let void_pointer = (types.graph.iter())
        .find_map(|(id, ty)| {
            matches!(ty, Type::Pointer { target } if *target == TypeId::VOID).then_some(id)
        })
        .expect("void *");
    let prototype = Prototype {
        name: "use".to_owned(),
        parameters: vec![Parameter::new(void_pointer, "void *", Some("p"))],
        returns: "void".into(),
        return_type: TypeId::VOID,
        frame_base: Some(FrameBase::CallFrameCfa),
        locals: vec![Local {
            name: "o".to_owned(),
            spelling: None,
            frame_offset: -0x20,
            size_bytes: Some(16),
            ty: types.ops,
            scopes: Vec::new(),
        }],
        ..Prototype::default()
    };
    let mut declarations = r2abi::Declarations::new(types.graph);
    declarations.declare_function(BASE, prototype);
    let mut open = program(FRAME_MEMBER_CALL, declarations);
    let roots = projected(&mut open);
    assert!(roots.contains(&("f".to_string(), "frame")), "{roots:?}");
    // `o.f` is never written, so the read has no C spelling and the call stays a gap; the contract is the gate.
    assert_eq!(member_call(&mut open), (true, 2, true));
}

/// D348 default-deny: a merged base, a read no member covers, and a load through `void *` root
/// nothing.
#[test]
fn a_root_no_projection_proves_projects_nothing() {
    let types = types();
    let node = || declaring("f", Some((types.node_pointer, "struct node *")), types.int);
    let holder = declaring(
        "f",
        Some((types.holder_pointer, "struct holder *")),
        types.int,
    );
    let roots = |code, declarations| projected(&mut program(code, declarations));
    let walked = roots(WALKED, node());
    assert!(
        walked.iter().all(|(_, root)| *root == "parameter"),
        "{walked:?}"
    );
    assert!(!walked.iter().any(|(name, _)| name == "val"), "{walked:?}");
    assert_eq!(
        roots(NARROW_VAL, node()),
        [("next".to_string(), "parameter")]
    );
    assert_eq!(
        roots(THROUGH_VOID, holder),
        [
            ("ops".to_string(), "parameter"),
            ("o".to_string(), "member")
        ]
    );
}

/// The stripped copy of a member call keeps its gap: no graph roots anything.
#[test]
fn a_stripped_member_call_stays_residual() {
    let functions = [("use", BASE, LOADED_MEMBER_CALL.len() as u64)];
    let mut open = OpenProgram::of(Literal::of_code(LOADED_MEMBER_CALL, &functions));
    assert!(!member_call(&mut open).0);
}

/// D272: `pddj` states a member call's declared arity, so the certifier grades it; the
/// stripped copy states none.
#[test]
fn pddj_states_a_member_calls_declared_arity() {
    let types = types();
    let declarations = declaring(
        "use",
        Some((types.holder_pointer, "struct holder *")),
        TypeId::VOID,
    );
    let declared = |mut open: OpenProgram<Literal>| {
        let rendering = open.rendered(BASE).expect("it renders");
        let answer = rendering.answer("use", BASE);
        (answer.calls.iter())
            .map(|call| (call.kind, call.arguments, call.declared))
            .collect::<Vec<_>>()
    };
    let typed = declared(program(LOADED_MEMBER_CALL, declarations));
    assert_eq!(typed, [("pointer", 2, Some(2))]);
    let functions = [("use", BASE, LOADED_MEMBER_CALL.len() as u64)];
    let stripped = declared(OpenProgram::of(Literal::of_code(
        LOADED_MEMBER_CALL,
        &functions,
    )));
    assert!(
        stripped.iter().all(|(_, _, declared)| declared.is_none()),
        "{stripped:?}"
    );
}
