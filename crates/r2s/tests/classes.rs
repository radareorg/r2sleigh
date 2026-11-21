//! A location's successive contents print as one local where the text proves the renaming
//! (ROADMAP D470): `fnv1a32`'s pointer is one carrier, its update written into it.

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

fn rendered(at: &str) -> String {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/coverage/pinned/hashes_gcc_x64_O2");
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", &format!("aa; pdd @ {at}")])
        .arg(binary)
        .output()
        .expect("the shell runs");
    assert!(done.status.success(), "{done:?}");
    String::from_utf8_lossy(&done.stdout).into_owned()
}

#[test]
fn fnv1a32_steps_one_pointer_and_copies_nothing_back() {
    let text = rendered("0x00401330");
    assert!(!text.contains("rdi_2"), "{text}");
    assert!(
        text.contains("rdi_1 = (uint64_t)((uint64_t)rdi_1 + (uint64_t)1U);"),
        "{text}"
    );
    assert!(!text.contains("rdi_1 = rdi_1;"), "{text}");
    assert!(
        text.contains("while ((uint8_t)((uint64_t)rsi_1 != (uint64_t)rdi_1));"),
        "{text}"
    );
}
