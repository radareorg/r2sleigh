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

/// An x86-64 relocatable object whose `f` calls an undeclared import and a function of its own.
fn relocated() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../r2image/tests/data/relocated.elf")
}

/// An AArch64 Mach-O whose dispatch calls through a register.
fn dispatching() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/code_pointer_table_O0")
}

/// Every note of every line, as `(mark cell, text)`.
fn notes(listing: &str) -> Vec<(char, String)> {
    let note = |note: &str| {
        let mut chars = note.chars();
        let cell = chars.next()?;
        Some((cell, chars.as_str().trim_start().to_owned()))
    };
    let line_notes = |line: &str| -> Vec<(char, String)> {
        let notes = line.split(" ; ").skip(1);
        notes.filter_map(note).collect()
    };
    listing.lines().flat_map(line_notes).collect()
}

/// Reader text by default (D567): one mark cell and no basis word; a refused call says why.
#[test]
fn a_default_listing_marks_each_note_and_names_no_basis() {
    let listing = piped(relocated(), "pdf @ sym.f");
    for basis in ["(certified", "(decoded", "(declared", "(solved", "(folded"] {
        assert!(!listing.contains(basis), "{basis}: {listing}");
    }
    let call = (listing.lines().find(|line| line.contains("0x08000040"))).expect("the call");
    // The operand spells no name for the stub, so the note names the import it refuses.
    let undeclared =
        " ; ! args of sym.imp.ext: the import has no declaration to state its arguments";
    assert!(call.ends_with(undeclared), "{call}");
    // `asm.proof` brings the basis back and moves no line.
    let proof = piped(relocated(), "e asm.proof=true; pdf @ sym.f");
    assert!(proof.contains("(certified"), "{proof}");
    assert_eq!(proof.lines().count(), listing.lines().count());
}

/// A refusal is `!` and an unknown `?`, never the space a fact that holds takes.
#[test]
fn a_refusal_or_an_unknown_never_takes_the_space_cell() {
    let listings = [
        piped(relocated(), "pdf @ sym.f"),
        piped(hashes(), "pdf @ 0x401330; pdf @ sym.siphash24"),
        piped(dispatching(), "pdf @ sym._table_dispatch"),
    ];
    let notes = listings.iter().flat_map(|listing| notes(listing));
    let mut refused = 0;
    for (cell, text) in notes {
        if text.starts_with("args: ") || text.starts_with("args of ") {
            assert_eq!(cell, '!', "{text}");
            refused += 1;
        }
        if text.starts_with("indirect branch unresolved") {
            assert_eq!(cell, '?', "{text}");
        }
    }
    assert!(
        refused >= 2,
        "the object's import call and the indirect `blr`"
    );
}
