//! What the frame model lets the rendering assume a callee cannot reach (doc/adr-frame-model.md).

#![cfg(feature = "sleigh")]

mod common;

use std::path::PathBuf;
use std::process::Command;

/// What `script` prints for one pinned fixture.
fn run(fixture: &str, script: &str) -> String {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/coverage/pinned")
        .join(fixture);
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(binary)
        .output()
        .expect("the shell runs");
    assert!(
        done.status.success(),
        "{}",
        String::from_utf8_lossy(&done.stderr)
    );
    String::from_utf8_lossy(&done.stdout).into_owned()
}

fn pdd(fixture: &str, function: &str) -> String {
    run(fixture, &format!("pdd @ {function}"))
}

fn afv(fixture: &str, function: &str) -> String {
    run(fixture, &format!("afv @ {function}"))
}

/// `shape_pointer_to_pointer` fills `uint64_t *rows[4]` with the addresses of four locals and
/// hands `rows` to a callee that indexes it. An escaped address may reach every object from it up
/// to a slot the compiler owns, so the locals, `rows` and `cursor` are one object: each row is a
/// store into it, and the callee's arithmetic from `rows` stays inside it (extent rule, merged).
/// Splitting `rows` into scalars rendered `&rows[0]` indexed past its object, and differed.
#[test]
fn every_row_of_an_array_whose_first_address_escapes_is_stored() {
    let function = "sym.shape_pointer_to_pointer";
    let (out, afv) = (
        pdd("shapes_gcc_x64_O0", function),
        afv("shapes_gcc_x64_O0", function),
    );
    // The 88 bytes from entry.sp-0x78 lie in one declared array, whatever the pipeline names it.
    let rows = -0x78;
    let object = common::array_spanning(&out, &afv, rows, rows + 88);
    assert!(object.is_some(), "{afv}\n{out}");
    // Rows 6 to 9 hold the addresses of the four words the object begins with.
    let writes = common::stack_writes(&out, &afv);
    for (row, local) in [(6, 0), (7, 8), (8, 16), (9, 24)] {
        let stored = writes.iter().any(|(at, value)| {
            *at == rows + row * 8 && common::entry_offset(&out, &afv, value) == Some(rows + local)
        });
        assert!(stored, "row {row}:\n{afv}\n{out}");
    }
}

/// Below the lowest object whose own address escapes, an escaped address may still reach down
/// (an interior address past its object's base), and nothing proves it does not: those accesses
/// render under an assumed extent and the proof counts them.
#[test]
fn accesses_to_an_object_of_unproven_extent_are_counted_as_assumed() {
    let out = pdd("shapes_gcc_x64_O0", "sym.shape_pointer_to_pointer");
    assert!(out.contains("assumed (frame extent unproven)"), "{out}");
}

/// `binary_operation table[3]` is read as `table[(a + index) % 3]`, which gcc spells as a
/// multiply-high by `0xaaaaaaaaaaaaaaab`. The quotient is exact (Granlund-Montgomery), so the
/// index is in `[0, 2]`, the layout is proven, and `table` is one array of three.
#[test]
fn a_table_indexed_by_a_remainder_is_one_array_of_its_proven_length() {
    let (fixture, function) = ("shapes_gcc_x64_O0", "sym.shape_function_pointer");
    let (out, afv) = (pdd(fixture, function), afv(fixture, function));
    // The frame lists the table as three words at entry.sp-0x28 (ADR D4: afv states each local).
    assert!(
        afv.lines()
            .any(|line| line == "var uint64_t[3] stack_m40 @ entry.sp-0x28"),
        "{afv}"
    );
    // Its second and third rows hold the addresses of `op_xor` and `op_mul`, by name or by value.
    let functions = run(fixture, "afl");
    let address = |symbol: &str| {
        functions
            .lines()
            .find(|line| line.ends_with(&format!(" sym.{symbol}")))
            .and_then(|line| common::literal(line.split_whitespace().next()?))
            .unwrap_or_else(|| panic!("{symbol}: {functions}"))
    };
    let writes = common::stack_writes(&out, &afv);
    for (row, symbol) in [(1, "op_xor"), (2, "op_mul")] {
        let holds = |value: &str| {
            common::bare(value) == format!("&{symbol}")
                || common::literal(value) == Some(address(symbol))
        };
        let stored = writes
            .iter()
            .any(|(at, value)| *at == -0x28 + row * 8 && holds(value));
        assert!(stored, "{symbol}:\n{afv}\n{out}");
    }
}
