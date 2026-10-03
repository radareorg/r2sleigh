use super::*;

use object::{Object as _, ObjectSymbol as _};

/// Built from `tests/data/dwarf_prototypes.c` with
/// `clang -target x86_64-unknown-linux-gnu -fuse-ld=lld -nostdlib -g -O1`.
/// It is linked rather than an object file because an object's debug
/// section offsets are relocations nothing has applied yet, so every name
/// in one reads as whatever sits at offset zero.
const PROTOTYPES: &[u8] = include_bytes!("../../tests/data/dwarf_prototypes.elf");
/// `tests/gold/review.c` at GCC 13.3.0 `-O0 -g`, the review fixture.
const REVIEW: &[u8] = include_bytes!("../../../../tests/fixtures/rv_O0g");
/// `tests/data/dwarf_graph.c` at GCC 13.3.0 `-O2 -g`; see its header.
const GRAPH: &[u8] = include_bytes!("../../tests/data/dwarf_graph.elf");
/// `tests/fixtures/src/two_units_{a,b}.c` at GCC 13.3.0 `-O0 -g`, one binary.
const TWO_UNITS: &[u8] = include_bytes!("../../../../tests/fixtures/two_units_O0g");

fn declarations(bytes: &[u8]) -> Declarations {
    read(&object::File::parse(bytes).expect("the fixture parses"))
}

/// Where the symbol table puts a function, which is where its body begins.
fn symbol(bytes: &[u8], name: &str) -> u64 {
    let file = object::File::parse(bytes).expect("the fixture parses");
    file.symbols()
        .find(|symbol| symbol.name() == Ok(name))
        .map(|symbol| symbol.address())
        .unwrap_or_else(|| panic!("no symbol {name}"))
}

/// Every function the declarations state under one name, for asking about a
/// fixture; the engine never looks one up this way.
fn named<'a>(found: &'a Declarations, name: &str) -> Vec<(u64, &'a Prototype)> {
    found
        .functions()
        .filter(|(_, prototype)| prototype.name == name)
        .collect()
}

fn only<'a>(found: &'a Declarations, name: &str) -> &'a Prototype {
    match named(found, name).as_slice() {
        [(_, prototype)] => prototype,
        other => panic!("{name}: {} declarations", other.len()),
    }
}

fn spelled(found: &Declarations, name: &str) -> String {
    let prototype = only(found, name);
    let parameters = prototype
        .parameters
        .iter()
        .map(|parameter| match &parameter.name {
            Some(called) => format!("{} {called}", parameter.spelling.as_written()),
            None => parameter.spelling.as_written().to_owned(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("{} {name}({parameters})", prototype.returns.as_written())
}

fn local<'a>(prototype: &'a Prototype, name: &str) -> &'a Local {
    prototype
        .locals
        .iter()
        .find(|local| local.name == name)
        .unwrap_or_else(|| panic!("no local {name}"))
}

const LP64: DataModel = DataModel::unix(64);

#[test]
fn a_declared_signature_is_read_with_its_own_spellings() {
    let found = declarations(PROTOTYPES);
    assert_eq!(spelled(&found, "add"), "int add(int a, int b)");
    assert_eq!(
        spelled(&found, "scale"),
        "ulong_t scale(ulong_t v, size_t n)"
    );
    assert_eq!(
        spelled(&found, "sum_point"),
        "int sum_point(const struct point * p)"
    );
    assert_eq!(
        spelled(&found, "pick"),
        "char * pick(char ** names, int index)"
    );
    assert_eq!(
        spelled(&found, "mean"),
        "double mean(const double * xs, int n)"
    );
}

#[test]
fn a_frame_variable_is_read_with_its_offset_and_its_type() {
    let found = declarations(PROTOTYPES);
    let shifted = only(&found, "shifted");
    assert_eq!(shifted.frame_base, Some(FrameBase::Register(6)));
    let moved = local(shifted, "moved");
    assert_eq!(
        moved.spelling.as_ref().map(r2abi::Spelled::as_written),
        Some("struct point")
    );
    assert!(moved.frame_offset < 0, "{moved:?}");
    // The record's extent is its declared size, so the slot has one.
    assert_eq!(moved.size_bytes, Some(8));
    // `i` is declared in the loop's own scope and `t` in the body's.
    let mean = only(&found, "mean");
    assert!(mean.locals.iter().any(|local| local.name == "t"));
    assert!(mean.locals.iter().any(|local| local.name == "i"));
}

#[test]
fn a_declaration_without_a_body_states_no_function() {
    // `counted` is declared and never defined, so it has no low address.
    assert!(named(&declarations(PROTOTYPES), "counted").is_empty());
}

/// `main` in the review fixture declares `unsigned v[4]`, three `struct node`
/// and `char buf[16]`; the reader used to decay every array to a pointer and
/// know a struct only by its tag, so none of them had an extent or a layout.
#[test]
fn a_local_array_and_a_local_struct_are_declared_whole() {
    let found = declarations(REVIEW);
    let graph = found.graph();
    let main = only(&found, "main");

    let v = local(main, "v");
    assert_eq!(v.size_bytes, Some(16));
    let Some(Type::Array {
        element,
        count: Some(4),
    }) = graph.resolved(v.ty)
    else {
        panic!("v is {:?}", graph.get(v.ty));
    };
    assert!(matches!(
        graph.resolved(*element),
        Some(Type::Scalar(Scalar {
            kind: ScalarKind::Unsigned,
            width: Width::Bits(32),
            ..
        }))
    ));
    assert_eq!(
        v.spelling.as_ref().map(|s| s.as_written()),
        Some("unsigned int[4]")
    );
    assert_eq!(local(main, "buf").size_bytes, Some(16));
    assert_eq!(local(main, "d").size_bytes, Some(24));

    let c = local(main, "c");
    assert_eq!(c.size_bytes, Some(24));
    let (node, _) = graph.peel(c.ty);
    let Some(Type::Record(record)) = graph.get(node) else {
        panic!("c is {:?}", graph.get(c.ty));
    };
    assert_eq!(record.tag.as_deref(), Some("node"));
    let offsets = record
        .members
        .iter()
        .map(|member| (member.name.as_deref(), member.offset_bits))
        .collect::<Vec<_>>();
    assert_eq!(
        offsets,
        [(Some("key"), 0), (Some("next"), 64), (Some("tag"), 128)]
    );
    // `next` points at the very node it is a member of.
    assert_eq!(
        graph.get(record.members[1].ty),
        Some(&Type::Pointer { target: node })
    );
    assert_eq!(graph.size_bits(record.members[2].ty, &LP64), Some(64));
}

/// A parameter the compiler keeps in the frame states where, and that is the
/// parameter's home before anything is proved about the body.
#[test]
fn a_parameter_kept_in_the_frame_states_its_home() {
    let found = declarations(REVIEW);
    let main = only(&found, "main");
    let homes = main
        .parameters
        .iter()
        .map(|parameter| (parameter.name.as_deref(), parameter.frame_offset))
        .collect::<Vec<_>>();
    assert_eq!(
        homes,
        [(Some("argc"), Some(-228)), (Some("argv"), Some(-240))]
    );
    let list_len = only(&found, "list_len");
    assert_eq!(
        list_len.parameters[0].spelling.as_written(),
        "const struct node *"
    );
}

/// The review fixture's globals, whose types the renderer refused for want
/// of a statement: `2 data object types refused`.
#[test]
fn an_object_at_a_fixed_address_is_declared_with_its_type() {
    let found = declarations(REVIEW);
    let graph = found.graph();
    let spelled = |name: &str| {
        let (_, object) = found
            .objects()
            .find(|(_, object)| object.name == name)
            .unwrap_or_else(|| panic!("no object {name}"));
        (graph.declaration(object.ty, name), object.size_bytes)
    };
    assert_eq!(
        spelled("g_counter"),
        (Some("int g_counter".to_owned()), Some(4))
    );
    assert_eq!(
        spelled("g_table"),
        (Some("int g_table[16]".to_owned()), Some(64))
    );
    assert_eq!(
        spelled("g_msg"),
        (Some("const char *g_msg".to_owned()), Some(8))
    );
    assert_eq!(
        found
            .object_at(symbol(REVIEW, "g_counter"))
            .map(|o| o.name.as_str()),
        Some("g_counter")
    );
}

/// GCC specialises `scaled` into a clone whose concrete DWARF instance names
/// nothing and types nothing itself: all of it is its abstract origin's. The
/// clone is declared at its own body, with the source's prototype, and with
/// where each parameter really arrives -- which is not where the prototype
/// would place it.
#[test]
fn a_clone_is_read_through_its_origin_and_says_where_its_parameters_arrive() {
    let found = declarations(GRAPH);
    let entry = symbol(GRAPH, "scaled.constprop.0.isra.0");
    let scaled = found.function_at(entry).expect("the clone is declared");
    assert_eq!(scaled.name, "scaled");
    let parameters = scaled
        .parameters
        .iter()
        .map(|parameter| {
            (
                parameter.name.as_deref(),
                parameter.spelling.as_written(),
                parameter.arrival,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        parameters,
        [
            (Some("p"), "const struct pair *", None),
            // DWARF numbers `rdx` one.
            (Some("factor"), "int", Some(Arrival::Register(1))),
            (Some("bias"), "int", Some(Arrival::Unpassed)),
        ]
    );
    assert_eq!(scaled.returns.as_written(), "long int");
}

#[test]
fn a_pointer_to_an_incomplete_type_and_to_code_are_declared() {
    let found = declarations(GRAPH);
    let graph = found.graph();
    let use_opaque = only(&found, "use_opaque");
    let Some(Type::Pointer { target }) = graph.get(use_opaque.parameters[0].ty) else {
        panic!("{:?}", use_opaque.parameters[0]);
    };
    assert_eq!(
        graph.get(*target),
        Some(&Type::Opaque {
            keyword: Keyword::Struct,
            tag: "opaque".to_owned(),
        })
    );
    let apply = only(&found, "apply");
    assert_eq!(
        apply.parameters[0].spelling.as_written(),
        "int (*)(int, int)"
    );
    let Some(Type::Pointer { target }) = graph.get(apply.parameters[0].ty) else {
        panic!("{:?}", apply.parameters[0]);
    };
    let Some(Type::Code(signature)) = graph.get(*target) else {
        panic!("{:?}", graph.get(*target));
    };
    assert!(signature.prototyped && !signature.variadic);
    assert_eq!(signature.parameters.len(), 2);
}

#[test]
fn a_bit_field_a_flexible_array_a_union_and_an_enum_keep_their_layouts() {
    let found = declarations(GRAPH);
    let graph = found.graph();
    let read_flags = only(&found, "read_flags");
    let Some(Type::Pointer { target }) = graph.get(read_flags.parameters[0].ty) else {
        panic!("{:?}", read_flags.parameters[0]);
    };
    let Some(Type::Record(flags)) = graph.resolved(*target) else {
        panic!("{:?}", graph.get(*target));
    };
    let members = flags
        .members
        .iter()
        .map(|member| (member.name.as_deref(), member.offset_bits, member.bit_size))
        .collect::<Vec<_>>();
    assert_eq!(
        members,
        [
            (Some("ready"), 0, Some(1)),
            (Some("mode"), 1, Some(3)),
            (Some("tag"), 8, None),
            (Some("values"), 32, None),
        ]
    );
    assert!(matches!(
        graph.get(flags.members[3].ty),
        Some(Type::Array { count: None, .. })
    ));
    let Some(Type::Record(word)) = graph.resolved(read_flags.parameters[1].ty) else {
        panic!("{:?}", read_flags.parameters[1]);
    };
    assert_eq!(word.kind, RecordKind::Union);
    assert!(word.members.iter().all(|member| member.offset_bits == 0));
    assert!(matches!(
        graph.resolved(read_flags.parameters[2].ty),
        Some(Type::Enum { tag: Some(tag), .. }) if tag == "colour"
    ));
    assert_eq!(
        graph.size_bits(read_flags.parameters[2].ty, &LP64),
        Some(32)
    );
}

#[test]
fn a_function_scope_static_and_a_two_dimensional_array_are_objects() {
    let found = declarations(GRAPH);
    let graph = found.graph();
    let object = |name: &str| {
        found
            .objects()
            .find(|(_, object)| object.name == name)
            .map(|(_, object)| object.clone())
            .unwrap_or_else(|| panic!("no object {name}"))
    };
    assert_eq!(object("calls").size_bytes, Some(4));
    let table = object("table");
    assert_eq!(table.size_bytes, Some(24));
    assert_eq!(
        graph.declaration(table.ty, "table").as_deref(),
        Some("int table[2][3]")
    );
    // The anonymous record is called by the only name the source gives it.
    let origin = object("origin");
    assert_eq!(
        graph.declaration(origin.ty, "origin").as_deref(),
        Some("point_t origin")
    );
    let (record, _) = graph.peel(origin.ty);
    assert_eq!(graph.tag(record), Some("point_t"));
}

/// Two units each define a `static helper`. Keyed by name, the second
/// replaced the first, and its frame was applied to the other body.
#[test]
fn two_static_functions_of_one_name_are_each_their_own_units() {
    let found = declarations(TWO_UNITS);
    let helpers = named(&found, "helper");
    assert_eq!(helpers.len(), 2);
    let file = object::File::parse(TWO_UNITS).expect("the fixture parses");
    let mut entries = file
        .symbols()
        .filter(|symbol| symbol.name() == Ok("helper"))
        .map(|symbol| symbol.address())
        .collect::<Vec<_>>();
    entries.sort_unstable();
    let shapes = entries
        .iter()
        .map(|entry| {
            let helper = found.function_at(*entry).expect("each body is declared");
            (
                helper.returns.as_written().to_owned(),
                helper.parameters.len(),
                helper
                    .locals
                    .iter()
                    .map(|local| local.name.clone())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    assert!(shapes.contains(&("int".to_owned(), 1, vec!["doubled".to_owned()])));
    assert!(shapes.contains(&(
        "double".to_owned(),
        2,
        vec!["total".to_owned(), "i".to_owned()]
    )));
}

#[test]
fn a_binary_with_no_debug_information_states_nothing() {
    // The same translation unit compiled without `-g`.
    const STRIPPED: &[u8] = include_bytes!("../../tests/data/dwarf_prototypes_stripped.elf");
    assert!(declarations(STRIPPED).is_empty());
    // And the graph fixture after `strip --strip-all`: every node kind above,
    // and nothing left to read any of them from.
    const GRAPH_STRIPPED: &[u8] = include_bytes!("../../tests/data/dwarf_graph_stripped.elf");
    assert!(declarations(GRAPH_STRIPPED).is_empty());
}
