//! What a listing looks like to a pipe and to a person (doc/adr-display.md).

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

/// A GCC-built x86-64 ELF carried in the tree, not stripped.
fn hashes() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/coverage/pinned/hashes_gcc_x64_O2")
}

/// The shell's stdout for `script`, run with stdout a pipe.
fn piped(binary: PathBuf, script: &str) -> String {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(binary)
        .env_remove("NO_COLOR")
        .output()
        .expect("the shell runs");
    assert!(done.status.success(), "{script}: {done:?}");
    String::from_utf8(done.stdout).expect("the listing is text")
}

/// `text` with every SGR sequence (`ESC [ ... m`) removed.
fn unpainted(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => {
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Plain mode (D581): a pipe gets no escape byte, and the text a terminal gets with its paint
/// removed; asking for colour still paints.
#[test]
fn a_piped_listing_is_the_painted_one_with_no_escape() {
    let plain = piped(hashes(), "pdf @ 0x401330");
    assert!(!plain.contains('\x1b'), "{plain}");
    assert!(plain.contains(" ; "), "the function has notes: {plain}");
    let painted = piped(hashes(), "e scr.color=1; pdf @ 0x401330");
    assert!(painted.contains('\x1b'), "{painted}");
    assert_eq!(unpainted(&painted), plain);
}
