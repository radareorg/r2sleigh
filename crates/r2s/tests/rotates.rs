//! A shift pair of complementary literal counts over one value prints as the rotate it is
//! (ROADMAP D473): murmur3's three rotates in the hashes fixture.

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

fn murmur3() -> String {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/hashes_gcc_x64_O2_stripped");
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", "aa; pdd @ 0x401680"])
        .arg(binary)
        .output()
        .expect("the shell runs");
    assert!(done.status.success(), "{done:?}");
    String::from_utf8_lossy(&done.stdout).into_owned()
}

#[test]
fn murmur3_prints_its_three_rotates() {
    let text = murmur3();
    assert_eq!(text.matches("r2sleigh_rotl32(").count(), 3, "{text}");
    // No left shift by k beside a right shift by 32 - k on one value is left.
    for k in 1..32u32 {
        let pair = (
            format!("<< (uint32_t){k}U) | "),
            format!(">> (uint32_t){}U)", 32 - k),
        );
        let paired = text
            .lines()
            .any(|line| line.contains(&pair.0) && line.contains(&pair.1));
        assert!(!paired, "a {k}/{} shift pair stays: {text}", 32 - k);
    }
}
