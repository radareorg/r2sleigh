//! What a binary's own debug information declares, as the shell renders it.
//!
//! The declarations reach the engine keyed by the address each body begins,
//! with their types as one graph: a struct parameter no longer costs a
//! function every type it has, an array local is one object, and two
//! functions of one name are two declarations. Each fixture is named in
//! `tests/fixtures/README.md`.

#![cfg(feature = "sleigh")]

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
    assert!(out.contains("int32_t c;"), "{out}");
    assert!(out.contains("return c;"), "{out}");
    assert!(!out.contains("(uint64_t)c"), "{out}");
    // The layout reached the graph, so the member has a name.
    assert!(out.contains("n->next"), "{out}");
    assert!(
        out.contains("struct node {"),
        "the rendering defines what it reads through:\n{out}"
    );
}

/// `main` declares `unsigned v[4]`, three `struct node`, `double d[3]` and
/// `char buf[16]`. Each is one object of its declared type, and each is what
/// its callee is handed.
#[test]
fn a_declared_array_and_a_declared_struct_are_one_object_each() {
    let out = run("rv_O0g", "pdd @ sym.main");
    for declared in [
        "uint32_t v[4];",
        "struct node c;",
        "double d[3];",
        "int8_t buf[16];",
        "sum_array(v, 4)",
        "avg(d, 3)",
        "list_len(&a)",
        "b.next = &c;",
    ] {
        assert!(out.contains(declared), "{declared} missing:\n{out}");
    }
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
    assert!(first.contains("int32_t helper(int32_t value)"), "{first}");
    assert!(first.contains("doubled"), "{first}");
    assert!(!first.contains("total"), "{first}");
    let second = run("two_units_O0g", "s 0x117c; pdd");
    assert!(
        second.contains("double helper(const double* values, int64_t count)"),
        "{second}"
    );
    assert!(second.contains("total"), "{second}");
    assert!(!second.contains("doubled"), "{second}");
}

/// Clang states `counter`'s locals against rbp, and `counter` spills no
/// parameter, so nothing but the prologue says where rbp points. The
/// prologue's proof restates them in entry coordinates, where the body's
/// accesses are found; without it the names never landed.
#[test]
fn frame_pointer_locals_are_placed_by_the_prologue() {
    let out = run("frame_pointer_locals_clang_O0g", "pdd @ sym.counter");
    for local in ["step", "total", " i"] {
        assert!(out.contains(local), "{local} missing:\n{out}");
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
