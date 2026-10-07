//! What the frame model lets the rendering assume a callee cannot reach (doc/adr-frame-model.md).

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

fn pdd(fixture: &str, function: &str) -> String {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/coverage/pinned")
        .join(fixture);
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", &format!("pdd @ {function}")])
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

/// `shape_pointer_to_pointer` fills `uint64_t *rows[4]` with the addresses of four locals and
/// hands `rows` to a callee that indexes it. An escaped address may reach every object from it up
/// to a slot the compiler owns, so the locals, `rows` and `cursor` are one object: each row is a
/// store into it, and the callee's arithmetic from `rows` stays inside it (extent rule, merged).
/// Splitting `rows` into scalars rendered `&rows[0]` indexed past its object, and differed.
#[test]
fn every_row_of_an_array_whose_first_address_escapes_is_stored() {
    let out = pdd("shapes_gcc_x64_O0", "sym.shape_pointer_to_pointer");
    assert!(out.contains("uint8_t stack_m120[88];"), "{out}");
    for (row, local) in [(6, ""), (7, " + 8"), (8, " + 16"), (9, " + 24")] {
        let store = format!(
            "r2sleigh_store_u64((uint8_t*)stack_m120 + {row} * sizeof(uint64_t), (uint64_t)stack_m120{local});"
        );
        assert!(out.contains(&store), "{store}:\n{out}");
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
    let out = pdd("shapes_gcc_x64_O0", "sym.shape_function_pointer");
    assert!(out.contains("uint64_t stack_m40[3];"), "{out}");
    assert!(out.contains("stack_m40[1] = (uint64_t)&op_xor;"), "{out}");
    assert!(out.contains("stack_m40[2] = (uint64_t)&op_mul;"), "{out}");
}
