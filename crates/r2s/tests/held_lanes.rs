//! What a call reads of an argument register, through the whole pipeline (D366).

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

fn rendered(fixture: &str, script: &str) -> String {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(fixture);
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(binary)
        .output()
        .expect("the shell runs");
    String::from_utf8_lossy(&done.stdout).into_owned()
}

/// `_main` hands `argc` through x20 to `_struct_nested_array`'s held `w2`; two later calls whose
/// complete interfaces state no x2 read none of it, so X0's unstated upper half spells no residual.
#[test]
fn an_argument_handed_to_a_held_lane_reads_no_upper_half() {
    let text = rendered("tests/fixtures/manual_limits_O2", "aa; pdd @ sym._main");
    assert!(text.contains("_struct_nested_array("), "{text}");
    assert!(!text.contains("r2sleigh_residual"), "{text}");
}
