//! A call through a function-pointer member of a declared pointer parameter takes the member's
//! type as its contract; anything the type does not state stays residual (ROADMAP D171, S32).

use crate::common;

use common::{BASE, Literal};
use r2abi::{Member, Record, RecordKind, Signature, StatedConvention, Type, TypeGraph, TypeId};
use r2engine::program::OpenProgram;
use r2ssa::{CallBoundaryRefusal, MemberCallRefusal, SourceCallResult};

/// `use_ops(struct ops *o)` writing three argument registers, then calling the member at 8.
const MEMBER_CALL: &[u8] = &[
    0x48, 0x83, 0xec, 0x08, // 1000 sub rsp, 8
    0x48, 0x8b, 0x47, 0x08, // 1004 mov rax, [rdi + 8]
    0x48, 0x8b, 0x37, // 1008 mov rsi, [rdi]
    0x48, 0x8b, 0x3f, // 100b mov rdi, [rdi]
    0xba, 0x07, 0x00, 0x00, 0x00, // 100e mov edx, 7
    0xff, 0xd0, // 1013 call rax
    0x48, 0x83, 0xc4, 0x08, // 1015 add rsp, 8
    0xc3, // 1019 ret
];

/// The same, calling the slot the member at 8 points at: a vtable's shape.
const SLOT_CALL: &[u8] = &[
    0x48, 0x83, 0xec, 0x08, // 1000 sub rsp, 8
    0x48, 0x8b, 0x47, 0x08, // 1004 mov rax, [rdi + 8]
    0x48, 0x8b, 0x37, // 1008 mov rsi, [rdi]
    0x48, 0x8b, 0x3f, // 100b mov rdi, [rdi]
    0xba, 0x07, 0x00, 0x00, 0x00, // 100e mov edx, 7
    0xff, 0x10, // 1013 call [rax]
    0x48, 0x83, 0xc4, 0x08, // 1015 add rsp, 8
    0xc3, // 1019 ret
];

/// `MEMBER_CALL` under Microsoft x64, `o` arriving in rcx.
const MS_ABI_MEMBER_CALL: &[u8] = &[
    0x48, 0x83, 0xec, 0x28, // 1000 sub rsp, 0x28
    0x48, 0x8b, 0x41, 0x08, // 1004 mov rax, [rcx + 8]
    0x48, 0x8b, 0x11, // 1008 mov rdx, [rcx]
    0x48, 0x8b, 0x09, // 100b mov rcx, [rcx]
    0x41, 0xb8, 0x07, 0x00, 0x00, 0x00, // 100e mov r8d, 7
    0xff, 0xd0, // 1014 call rax
    0x48, 0x83, 0xc4, 0x28, // 1016 add rsp, 0x28
    0xc3, // 101a ret
];

/// How the member at 8 is declared.
#[derive(Clone, Copy)]
enum Shape {
    /// `void (*)(void *, void *)`.
    TwoPointers,
    /// `void (*)()`.
    Unprototyped,
    /// `void (*)(void *, ...)`.
    Variadic,
    /// `struct big (*)(void *, void *)`, a record no register holds.
    RecordResult,
    /// `void (__attribute__((ms_abi)) *)(void *, void *)`: code under a convention of its own.
    MsAbiMember,
    /// `TwoPointers` in a function declared `ms_abi`, whose members' convention it is not.
    MsAbiCaller,
}

/// `struct ops { void *o; <shape> f; }` and `void use_ops(struct ops *o)` at `BASE`.
fn declaring(shape: Shape) -> r2abi::Declarations {
    use r2abi::{Parameter, Prototype, Scalar, ScalarKind, Width};
    let mut graph = TypeGraph::new();
    let void_pointer = graph.add(Type::Pointer {
        target: TypeId::VOID,
    });
    let long = graph.add(Type::Scalar(Scalar {
        kind: ScalarKind::Signed,
        width: Width::Bits(64),
        name: Some("long int".to_owned()),
    }));
    let field = |name: &str, ty, at| Member {
        name: Some(name.to_owned()),
        ty,
        offset_bits: at,
        bit_size: None,
    };
    let big = graph.add(Type::Record(Record {
        kind: RecordKind::Struct,
        tag: Some("big".to_owned()),
        size_bytes: 24,
        members: vec![
            field("a", long, 0),
            field("b", long, 64),
            field("c", long, 128),
        ],
    }));
    let (returns, parameters, variadic, prototyped) = match shape {
        Shape::TwoPointers | Shape::MsAbiMember | Shape::MsAbiCaller => {
            (TypeId::VOID, vec![void_pointer; 2], false, true)
        }
        Shape::Unprototyped => (TypeId::VOID, Vec::new(), false, false),
        Shape::Variadic => (TypeId::VOID, vec![void_pointer], true, true),
        Shape::RecordResult => (big, vec![void_pointer; 2], false, true),
    };
    let code = graph.add(Type::Code(Signature {
        returns,
        parameters,
        variadic,
        prototyped,
        convention: match shape {
            Shape::MsAbiMember => StatedConvention::LlvmWin64,
            _ => StatedConvention::Normal,
        },
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
    let prototype = Prototype {
        name: "use_ops".to_owned(),
        parameters: vec![Parameter::new(ops_pointer, "struct ops *", Some("o"))],
        returns: "void".into(),
        return_type: TypeId::VOID,
        convention: match shape {
            Shape::MsAbiCaller => StatedConvention::LlvmWin64,
            _ => StatedConvention::Normal,
        },
        ..Prototype::default()
    };
    let mut declarations = r2abi::Declarations::new(graph);
    declarations.declare_function(BASE, prototype);
    declarations
}

fn program(code: &'static [u8], shape: Option<Shape>) -> OpenProgram<Literal> {
    let functions = [("use_ops", BASE, code.len() as u64)];
    let literal = Literal::of_code(code, &functions);
    OpenProgram::of(match shape {
        Some(shape) => literal.with_declarations(declaring(shape)),
        None => literal,
    })
}

/// What r2ssa states of the one call, and the boundary its contract (or the convention) gives it.
struct Seen {
    row: Option<Result<r2ssa::MemberCall, MemberCallRefusal>>,
    arguments: usize,
    arguments_proven: bool,
    result: Option<SourceCallResult>,
    refusal: Option<CallBoundaryRefusal>,
    text: String,
}

fn seen(code: &'static [u8], shape: Option<Shape>) -> Seen {
    let mut open = program(code, shape);
    let prepared = open.prepared(BASE).expect("it prepares");
    let shared = prepared.artifact().shared_artifact();
    let (&site, _) = (shared.facts().call_sites.by_id.iter().next()).expect("one call");
    let boundary = &shared.facts().boundaries.calls[&site];
    let text = (open.rendered(BASE).expect("it renders").response.output).into_text();
    Seen {
        row: shared.member_calls().get(site),
        arguments: boundary.arguments.len(),
        arguments_proven: boundary.arguments_proven,
        result: boundary.result_kind,
        refusal: boundary.refusal,
        text,
    }
}

/// The member's type states two pointers and no result: the call passes 2 arguments though the
/// caller also wrote rdx, and returns nothing.
#[test]
fn a_member_call_takes_the_members_type_as_its_contract() {
    let seen = seen(MEMBER_CALL, Some(Shape::TwoPointers));
    assert!(matches!(seen.row, Some(Ok(_))), "{:?}", seen.row);
    assert!(seen.arguments_proven);
    assert_eq!(seen.arguments, 2);
    assert_eq!(seen.result, Some(SourceCallResult::Void));
    assert_eq!(seen.refusal, None);
    assert!(!seen.text.contains("r2dec gap"), "{}", seen.text);
}

/// What the member's type leaves unstated keeps the convention's count from the registers.
#[test]
fn a_member_whose_type_states_no_contract_stays_residual() {
    let refused = [
        (MEMBER_CALL, Some(Shape::Unprototyped), Some(Ok(()))),
        (MEMBER_CALL, Some(Shape::Variadic), Some(Ok(()))),
        (MEMBER_CALL, Some(Shape::RecordResult), Some(Ok(()))),
        (
            MEMBER_CALL,
            Some(Shape::MsAbiMember),
            Some(Err(MemberCallRefusal::MemberNotCode)),
        ),
        (MS_ABI_MEMBER_CALL, Some(Shape::MsAbiCaller), Some(Ok(()))),
        (
            SLOT_CALL,
            Some(Shape::TwoPointers),
            Some(Err(MemberCallRefusal::TargetNotProjected)),
        ),
        // A recovered interface's graph types no member.
        (
            MEMBER_CALL,
            None,
            Some(Err(MemberCallRefusal::TargetNotProjected)),
        ),
    ];
    for (index, (code, shape, row)) in refused.into_iter().enumerate() {
        let seen = seen(code, shape);
        assert_eq!(seen.row.map(|row| row.map(|_| ())), row, "{index}");
        assert!(!seen.arguments_proven, "{index}");
        assert_eq!(
            seen.refusal,
            Some(CallBoundaryRefusal::CountFromRegisters),
            "{index}"
        );
        assert!(seen.text.contains("r2dec gap"), "{index}: {}", seen.text);
    }
}
