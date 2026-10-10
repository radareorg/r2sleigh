//! What a binary's own debug information declares, as the shell renders it.
//!
//! The declarations reach the engine keyed by the address each body begins,
//! with their types as one graph: a struct parameter no longer costs a
//! function every type it has, an array local is one object, and two
//! functions of one name are two declarations. Each fixture is named in
//! `tests/fixtures/README.md`.

#![cfg(feature = "sleigh")]

mod common;

use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

/// Run one script over one fixture and return everything it printed.
fn run(name: &str, script: &str) -> String {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(fixture(name))
        .output()
        .expect("the shell runs");
    let out =
        String::from_utf8_lossy(&done.stdout).into_owned() + &String::from_utf8_lossy(&done.stderr);
    assert!(done.status.success(), "`{script}` on {name} failed:\n{out}");
    out
}

/// `list_len(const struct node *n)` keeps `int c` and returns it. A pointer
/// to a struct the declaration could not intern used to refuse the whole
/// graph, so `c` became `uint32_t` and the result the full carrier.
#[test]
fn a_struct_parameter_costs_the_function_none_of_its_types() {
    let out = run("rv_O0g", "pdd @ sym.list_len");
    assert!(
        out.contains("int32_t list_len(const struct node* n)"),
        "{out}"
    );
    // `c` is the declared `int` at entry.sp-0xc, and the result is the four bytes there.
    let afv = run("rv_O0g", "afv @ sym.list_len");
    assert!(
        afv.lines()
            .any(|line| line == "var int32_t c @ entry.sp-0xc"),
        "{afv}"
    );
    let result = common::returned(&out).unwrap_or_default();
    assert_eq!(common::read_offset(&out, &afv, result), Some(-0xc), "{out}");
    assert!(!out.contains("(uint64_t)c"), "{out}");
    // `n` is one variable that walks the list: its home is written in the
    // loop, so no read inside it is the value `n` was entered with. (`n->next`
    // used to appear through exactly that stale identity -- the reload taken
    // for the parameter -- and comes back when a load is typed by the
    // declared pointee of the variable it reads through.)
    let by_name =
        out.contains("while ((uint64_t)n != 0)") && out.contains("n = (const struct node*)");
    // ADR D4's one `frame` array: the slot afv lists at `struct node*` takes the entry `n` once and
    // a loaded successor after, and nothing else reads the entry `n`.
    let home = (common::afv_locals(&afv).into_values()).find(|(_, ty)| ty == "struct node*");
    let writes = common::stack_writes(&out, &afv);
    let at_home = (writes.iter())
        .filter(|(at, _)| home.as_ref().is_some_and(|(home, _)| at == home))
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>();
    let entry_reads = (out.split(|c: char| !c.is_ascii_alphanumeric() && c != '_'))
        .filter(|word| *word == "n")
        .count();
    let by_home = matches!(at_home.as_slice(), [entered, walked]
        if common::bare(entered) == "n" && !common::starts_from(&out, walked, "n"))
        && entry_reads == 2;
    assert!(by_name || by_home, "{afv}\n{out}");
    assert!(!out.contains("n->next"), "{out}");
    assert!(!out.contains("r2sleigh_residual"), "{out}");
    assert!(
        out.contains("struct node {"),
        "the rendering defines what it reads through:\n{out}"
    );
}

/// Staged spells a parameter, a callee and a function pointer at their declared types and defines
/// each tag it spells once, reading no member the declaration does not type at the access.
#[test]
fn staged_declares_the_struct_and_function_pointer_types_the_source_states() {
    let list_len = run("rv_O0g", "e dec.pipeline=staged; pdd @ sym.list_len");
    assert!(
        list_len.contains("int32_t list_len(const struct node* n)"),
        "{list_len}"
    );
    assert!(
        !list_len.contains("->") && !list_len.contains(".next"),
        "{list_len}"
    );
    let main = run("rv_O0g", "e dec.pipeline=staged; pdd @ sym.main");
    for c in [&list_len, &main] {
        assert_eq!(c.matches("struct node {").count(), 1, "{c}");
        assert!(c.find("struct node {") < c.find("struct node*"), "{c}");
    }
    assert!(
        main.contains("int32_t list_len(const struct node*);"),
        "{main}"
    );
    assert!(
        main.contains("int32_t dispatch(int32_t(*)(int32_t, int32_t), int32_t);"),
        "{main}"
    );
    let dispatch = run("rv_O0g", "e dec.pipeline=staged; pdd @ sym.dispatch");
    assert!(
        dispatch.contains("int32_t dispatch(int32_t (*fn)(int32_t, int32_t), int32_t a)"),
        "{dispatch}"
    );
}

/// `main` declares `unsigned v[4]`, three `struct node`, `double d[3]` and
/// `char buf[16]`. Each is one object of its declared type, and each is what
/// its callee is handed.
#[test]
fn a_declared_array_and_a_declared_struct_are_one_object_each() {
    let out = run("rv_O0g", "pdd @ sym.main");
    // Each object is one local of its declared type (ADR D4: afv states each local of the frame).
    let afv = run("rv_O0g", "afv @ sym.main");
    let locals = common::afv_locals(&afv);
    for (name, declared) in [
        ("v", "uint32_t[4]"),
        ("c", "struct node"),
        ("d", "double[3]"),
        ("buf", "char[16]"),
    ] {
        let ty = locals.get(name).map(|(_, ty)| ty.as_str());
        assert_eq!(ty, Some(declared), "{name}:\n{afv}");
    }
    let at = |name: &str| locals.get(name).map(|(offset, _)| *offset);
    // Each callee is handed the object itself, however the pipeline spells its address.
    for (callee, object, count) in [
        ("sum_array", "v", Some(4)),
        ("avg", "d", Some(3)),
        ("list_len", "a", None),
    ] {
        let arguments = common::call_arguments(&out, callee).unwrap_or_default();
        let first = arguments.first().map(String::as_str).unwrap_or_default();
        assert_eq!(
            common::entry_offset(&out, &afv, first),
            at(object),
            "{callee}:\n{out}"
        );
        let second = arguments
            .get(1)
            .and_then(|argument| common::literal(argument));
        assert_eq!(second, count, "{callee}:\n{out}");
    }
    // `b.next`, eight bytes into `b`, holds `&c`.
    let linked = out.contains("b.next = &c;")
        || common::stack_writes(&out, &afv)
            .iter()
            .any(|(written, value)| {
                Some(*written) == at("b").map(|b| b + 8)
                    && common::entry_offset(&out, &afv, value) == at("c")
            });
    assert!(linked, "{afv}\n{out}");
    // One array, not four scalars that happen to sit together.
    assert!(!out.contains("stack_m196"), "{out}");
    // `c.tag` is `char tag[8]`, which one eight-byte store does not assign
    // in C; the store is bytes of `c`, not a member.
    assert!(!out.contains("c.tag ="), "{out}");
    // `dispatch` is declared to take `int (*fn)(int, int)`, and `main` hands
    // it the address of `add`: a bare integer there is not C.
    assert!(
        out.contains("int32_t dispatch(int32_t(*)(int32_t, int32_t), int32_t);"),
        "{out}"
    );
    assert!(!out.contains("dispatch(0x11a9"), "{out}");
}

/// The review fixture's globals are typed by their DWARF: they rendered as
/// `extern char name[]` under "2 data object types refused".
#[test]
fn a_global_is_declared_with_the_type_its_debug_information_states() {
    let out = run("rv_O0g", "pdd @ sym.fill");
    assert!(out.contains("extern int32_t g_counter;"), "{out}");
    assert!(out.contains("extern int32_t g_table[16];"), "{out}");
    assert!(!out.contains("data object types refused"), "{out}");
    assert!(
        out.contains("2 data object types supplied by the source"),
        "{out}"
    );
}

/// Two units each define a `static helper`. Keyed by name, the second
/// replaced the first, and its frame and types were applied to the other
/// body; keyed by address, each body renders its own unit's declaration.
#[test]
fn two_functions_of_one_name_are_each_declared_by_their_own_unit() {
    let first = run("two_units_O0g", "s 0x1149; pdd");
    let first_frame = run("two_units_O0g", "s 0x1149; afv");
    assert!(first.contains("int32_t helper(int32_t value)"), "{first}");
    assert!(
        common::afv_locals(&first_frame).contains_key("doubled"),
        "{first_frame}"
    );
    assert!(
        !first.contains("total") && !first_frame.contains("total"),
        "{first}"
    );
    let second = run("two_units_O0g", "s 0x117c; pdd");
    let second_frame = run("two_units_O0g", "s 0x117c; afv");
    assert!(
        second.contains("double helper(const double* values, int64_t count)"),
        "{second}"
    );
    let total = common::afv_locals(&second_frame).get("total").cloned();
    assert_eq!(
        total.as_ref().map(|(_, ty)| ty.as_str()),
        Some("double"),
        "{second_frame}"
    );
    // The double leaves in XMM0's low lane, which is the convention's slot:
    // returned as the value, not rebuilt from the vector register.
    let result = common::returned(&second).unwrap_or_default();
    let read = common::read_offset(&second, &second_frame, result);
    assert_eq!(read, total.map(|(offset, _)| offset), "{second}");
    assert!(!second.contains("__uint128_t"), "{second}");
    assert!(
        !second.contains("doubled") && !second_frame.contains("doubled"),
        "{second}"
    );
}

/// Clang states `counter`'s locals against rbp, and `counter` spills no
/// parameter, so nothing but the prologue says where rbp points. The
/// prologue's proof restates them in entry coordinates, where the body's
/// accesses are found; without it the names never landed.
#[test]
fn frame_pointer_locals_are_placed_by_the_prologue() {
    let out = run("frame_pointer_locals_clang_O0g", "pdd @ sym.counter");
    let afv = run("frame_pointer_locals_clang_O0g", "afv @ sym.counter");
    // Each local is placed at its entry offset, and the body's first write to it lands there.
    let locals = common::afv_locals(&afv);
    let writes = common::stack_writes(&out, &afv);
    for (local, first) in [("step", 3), ("total", 10), ("i", 0)] {
        let at = locals.get(local).map(|(offset, _)| *offset);
        assert!(at.is_some(), "{local} missing:\n{afv}");
        let written = writes.iter().find(|(offset, _)| Some(*offset) == at);
        let value = written.and_then(|(_, value)| common::constant_of(&out, value));
        assert_eq!(value, Some(first), "{local}:\n{afv}\n{out}");
    }
}

/// The review fixture after `strip --strip-all`: no function states a
/// declared name or a declared layout, and every one still renders.
#[test]
fn without_debug_information_nothing_declared_appears() {
    // The unstripped build's symbol table says where each function begins.
    for address in ["0x1277", "0x1549", "0x1391", "0x11c1"] {
        let out = run("rv_O0g_stripped", &format!("s {address}; pdd"));
        for declared in ["struct node", "v[4]", "buf[16]", "g_table"] {
            assert!(!out.contains(declared), "{address}: {declared}:\n{out}");
        }
        assert!(!out.contains("panicked"), "{address}:\n{out}");
    }
}

/// A declared `double` argument is passed, whether the caller writes the lane or hands on its own formal (B3).
#[test]
fn a_declared_double_argument_reaches_its_call() {
    for name in ["float_calls_zig_x86_64_O2g", "float_calls_zig_aarch64_O2g"] {
        let call_store = run(name, "pdd @ sym.call_store");
        assert!(
            !call_store.contains("r2sleigh refused"),
            "{name}:\n{call_store}"
        );
        assert!(call_store.contains("store("), "{name}:\n{call_store}");
        assert!(call_store.contains(", p);"), "{name}:\n{call_store}");
        let forward = run(name, "pdd @ sym.forward");
        assert!(forward.contains("store(x, p);"), "{name}:\n{forward}");
        assert!(!forward.contains("r2sleigh refused"), "{name}:\n{forward}");
    }
}

/// A declared `double` result is certified when its slot is the low lane of the root the body merges or writes (B3).
#[test]
fn a_declared_double_result_is_returned() {
    for name in [
        "float_returns_zig_x86_64_O2g",
        "float_returns_zig_aarch64_O2g",
    ] {
        let out = run(name, "pdd @ sym.loop_sum");
        assert!(!out.contains("r2sleigh refused"), "{name}:\n{out}");
        assert!(
            out.contains("double loop_sum(const double* v, int32_t n)"),
            "{name}:\n{out}"
        );
    }
}

/// An argument moved as a whole register holds the slot that is that register's low lane (B3).
/// x86-64's `movaps` copies the register lane by lane, and the lanes in order are the source's bits (P5).
#[test]
fn a_double_moved_as_its_whole_register_is_the_argument() {
    let aarch64 = run("float_moves_zig_aarch64_O2g", "pdd @ sym.swap_call");
    assert!(aarch64.contains("return scale(b, a);"), "{aarch64}");
    let x86_64 = run("float_moves_zig_x86_64_O2g", "pdd @ sym.swap_call");
    assert!(x86_64.contains("return scale(b, a);"), "{x86_64}");
    assert!(!x86_64.contains("__uint128_t"), "{x86_64}");
}

/// A load from bytes the program never writes reads what the file holds: `x + 1.0`, not a read of
/// `.rodata` (P5). A slot the loader fills is still read at its address (below).
#[test]
fn a_constant_loaded_from_read_only_data_is_the_literal() {
    // 1.0 is added to `x`: legacy folds the literal, staged spells its bits as the float (P5, #90).
    let legacy = run("float_returns_zig_x86_64_O2g", "pdd @ sym.twice_half");
    assert!(legacy.contains("x + 1.0;"), "{legacy}");
    let staged = run(
        "float_returns_zig_x86_64_O2g",
        "e dec.pipeline=staged; pdd @ sym.twice_half",
    );
    assert!(
        staged.contains("half(x + r2sleigh_float_from_bits_64((uint64_t)0x3ff0000000000000U))"),
        "{staged}"
    );
    // And nothing reads `.rodata` for it, by either spelling of a load.
    for out in [legacy, staged] {
        assert!(!out.contains("*(uint64_t*)0x"), "{out}");
        assert!(
            !out.contains("r2sleigh_load_u64((void*)(uint64_t)0x"),
            "{out}"
        );
    }
}

/// `_init` reads `__gmon_start__`'s global offset table slot to see whether profiling is linked.
/// The slot is a word the loader fills, named by the relocation that fills it, not the function:
/// the read is of the slot's address, never `&__gmon_start__`.
#[test]
fn a_slot_the_loader_fills_is_read_at_its_address() {
    let out = run("frame_pointer_locals_clang_O0g", "pdd @ sym._init");
    assert!(!out.contains("&__gmon_start__"), "{out}");
    assert!(common::reads_at(&out, 0x3fd0, 64), "{out}");
}
