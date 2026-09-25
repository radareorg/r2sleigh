//! What the shell says the container states, checked against the platform's own tools.
//!
//! Each fixture is one the repository ships as bytes, and each expectation is
//! what `readelf`, `dyld_info` or radare2 itself says of it, so the shell's
//! spelling is diffable against radare2 and its facts against the format.

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

/// The shell's standard output for one script over one fixture.
fn run(name: &str, script: &str) -> String {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(fixture(name))
        .output()
        .expect("the shell runs");
    assert!(
        done.status.success() || script == "q",
        "`{script}` on {name}: {}",
        String::from_utf8_lossy(&done.stderr)
    );
    String::from_utf8_lossy(&done.stdout).into_owned()
}

/// The rows of a table: the lines after its rule.
fn rows(out: &str) -> Vec<&str> {
    out.lines()
        .skip_while(|line| !line.starts_with("---"))
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .collect()
}

#[test]
fn ir_lists_every_record_with_its_type_offset_and_addend() {
    // `readelf -r rv_O0g`: thirteen, four of them R_X86_64_RELATIVE, which
    // name no symbol and are spelled, as radare2 spells them, by the address
    // they write.
    let out = run("rv_O0g", "ir");
    let rows = rows(&out);
    assert_eq!(rows.len(), 13, "{out}");
    for (vaddr, paddr, target) in [
        ("0x00003da0", "0x00002da0", "0x000011a0"),
        ("0x00003da8", "0x00002da8", "0x00001160"),
        ("0x00004008", "0x00003008", "0x00004008"),
        ("0x00004018", "0x00003018", "0x00002008"),
    ] {
        let row = format!("{vaddr} {paddr} ADD_64 8      {target}");
        assert!(rows.contains(&row.as_str()), "{row} missing:\n{out}");
    }
    assert!(
        rows.contains(&"0x00003fc8 0x00002fc8 SET_64 7     printf"),
        "{out}"
    );
    // In address order, as radare2 lists them.
    let addresses: Vec<&str> = rows.iter().map(|row| &row[..10]).collect();
    assert!(addresses.is_sorted(), "{out}");
}

#[test]
fn ir_never_lists_a_mach_o_stub() {
    // `__stubs` of manual_limits_O0 is code at 0x100000fd8; the bind is in
    // `__got` and the two rebases in `__const`.
    let out = run("manual_limits_O0", "ir");
    let rows = rows(&out);
    assert_eq!(rows.len(), 3, "{out}");
    assert!(!out.contains("0x100000fd8"), "{out}");
    assert!(rows[0].starts_with("0x100004000") && rows[0].ends_with("_memcpy"));
}
