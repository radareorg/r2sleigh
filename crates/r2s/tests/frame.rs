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

/// `shape_pointer_to_pointer` fills `uint64_t *rows[4]` and hands `rows` to a callee that indexes
/// it. The partition sees four 8-byte slots and only the first one's address escapes, but nothing
/// proves where `rows` ends, so every row is reachable and each store stays. Dropping the last
/// three made the callee read uninitialised rows (equivalence: a fault at `rows[1]`).
#[test]
fn every_row_of_an_array_whose_first_address_escapes_is_stored() {
    let out = pdd("shapes_gcc_x64_O0", "sym.shape_pointer_to_pointer");
    for row in ["stack_m72", "stack_m64", "stack_m56", "stack_m48"] {
        assert!(out.contains(&format!("{row} = ")), "{row}:\n{out}");
    }
}

/// Nothing proves `rows` ends where the partition says, so the proof counts every access to it as
/// rendered under an assumed extent rather than as proven.
#[test]
fn accesses_to_an_object_of_unproven_extent_are_counted_as_assumed() {
    let out = pdd("shapes_gcc_x64_O0", "sym.shape_pointer_to_pointer");
    assert!(out.contains("assumed (frame extent unproven)"), "{out}");
}
