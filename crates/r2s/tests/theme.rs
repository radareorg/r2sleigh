//! One theme table at each `scr.color` depth (D569, doc/adr-display.md "Colour roles").

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

/// A GCC-built x86-64 ELF carried in the tree, not stripped.
fn hashes() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/coverage/pinned/hashes_gcc_x64_O2")
}

/// An x86-64 relocatable object whose `f` calls an undeclared import.
fn relocated() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../r2image/tests/data/relocated.elf")
}

/// The shell's stdout and exit status for `script`, run with stdout a pipe.
fn piped(binary: PathBuf, script: &str) -> (String, bool) {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(binary)
        .env_remove("NO_COLOR")
        .output()
        .expect("the shell runs");
    let out = String::from_utf8(done.stdout).expect("the listing is text");
    (out, done.status.success())
}

/// The listing's line holding `address`, from its address on: the rail and lanes are layout.
fn line_at(listing: &str, address: &str) -> String {
    let line = listing.lines().find(|line| line.contains(address));
    let line = line.unwrap_or_else(|| panic!("{address} in {listing}"));
    let at = line.find(address).expect("the address");
    let start = match line[..at].ends_with('m') {
        true => line[..at].rfind('\x1b').expect("the escape before it"),
        false => at,
    };
    line[start..].to_owned()
}

/// A bound note's `~` is painted in `ProofBound` at depths 1 to 3, and plain at 0.
#[test]
fn a_bound_mark_is_painted_at_each_depth() {
    let expected = [
        (
            0,
            "0x00401995      48c1e730       shl rdi, 0x30               ; ~ defines rdi in [0x0, 0xff000000000000]",
        ),
        (
            1,
            "\x1b[32m0x00401995\x1b[0m      48c1e730       shl \x1b[36mrdi\x1b[0m, \
             \x1b[33m0x30\x1b[0m               ; \x1b[94m~\x1b[0m defines rdi in [0x0, 0xff000000000000]",
        ),
        (
            2,
            "\x1b[38;5;71m0x00401995\x1b[0m      48c1e730       shl \x1b[38;5;37mrdi\x1b[0m, \
             \x1b[38;5;178m0x30\x1b[0m               ; \x1b[38;5;74m~\x1b[0m defines rdi in [0x0, 0xff000000000000]",
        ),
        (
            3,
            "\x1b[38;2;95;175;95m0x00401995\x1b[0m      48c1e730       shl \
             \x1b[38;2;0;175;175mrdi\x1b[0m, \x1b[38;2;215;175;0m0x30\x1b[0m               ; \
             \x1b[38;2;86;180;233m~\x1b[0m defines rdi in [0x0, 0xff000000000000]",
        ),
    ];
    for (depth, want) in expected {
        let script = format!("e scr.color={depth}; pdf @ sym.siphash24");
        let (listing, ok) = piped(hashes(), &script);
        assert!(ok, "e scr.color={depth} is accepted");
        assert_eq!(line_at(&listing, "0x00401995"), want, "scr.color={depth}");
    }
}

/// A refusal is a background cell, and its reason is painted in `ProofReason`.
#[test]
fn a_refusal_cell_and_its_reason_are_painted() {
    let (listing, ok) = piped(relocated(), "e scr.color=1; pdf @ sym.f");
    assert!(ok);
    let call = line_at(&listing, "0x08000040");
    let refused = " ; \x1b[41;30m!\x1b[0m \x1b[39margs of sym.imp.ext: \
                   the import has no declaration to state its arguments\x1b[0m";
    assert!(call.ends_with(refused), "{call:?}");
    let (listing, _) = piped(relocated(), "e scr.color=2; pdf @ sym.f");
    let call = line_at(&listing, "0x08000040");
    assert!(call.contains("\x1b[48;5;88;38;5;231m!\x1b[0m"), "{call:?}");
}

/// `scr.color` takes radare2's 0 to 3 and refuses anything else, keeping the value it had.
#[test]
fn scr_color_takes_radare2s_four_depths() {
    let (out, ok) = piped(
        hashes(),
        "e scr.color=2; e scr.color; e scr.color=3; e scr.color",
    );
    assert!(ok);
    assert_eq!(out, "2\n3\n");
    let (out, _) = piped(hashes(), "e scr.color=4; e scr.color");
    assert_eq!(out, "0\n");
}

/// `ao`'s notes and `pd?`'s legend paint each mark cell in the role `pdf` paints it, and print
/// the same bytes unpainted in a pipe.
#[test]
fn ao_notes_and_the_pd_legend_paint_their_mark_cells() {
    let said = "args of sym.imp.ext: the import has no declaration to state its arguments";
    let (out, ok) = piped(relocated(), "e scr.color=1; ao @ 0x08000040");
    assert!(ok);
    let painted = format!("\n  \x1b[41;30m!\x1b[0m \x1b[39m{said}\x1b[0m\n");
    assert!(out.contains(&painted), "{out:?}");
    let (out, _) = piped(relocated(), "ao @ 0x08000040");
    assert!(out.contains(&format!("\n  ! {said}\n")), "{out:?}");
    let (legend, ok) = piped(relocated(), "e scr.color=1; pd?");
    assert!(ok);
    assert!(
        legend.contains("\n\x1b[41;30m!\x1b[0m  refused; the reason follows"),
        "{legend:?}"
    );
    assert!(legend.contains("\n(space)  holds"), "{legend:?}");
    let (legend, _) = piped(relocated(), "pd?");
    assert!(
        legend.contains("\n!  refused; the reason follows"),
        "{legend:?}"
    );
}

/// `scr.color.grep=true` keeps `pdd`'s colour and rails through a row range, as radare2 keeps
/// colour under it; false, its default, greps the plain text.
#[test]
fn scr_color_grep_keeps_the_painted_rows() {
    let keys = "e scr.color=1; e asm.rails=true";
    let (whole, ok) = piped(hashes(), &format!("{keys}; pdd @ sym.fnv1a32"));
    assert!(
        ok && whole.contains('\x1b') && whole.contains('│'),
        "{whole:?}"
    );
    let rows: String = whole
        .lines()
        .skip(3)
        .take(5)
        .map(|line| format!("{line}\n"))
        .collect();
    let script = format!("{keys}; e scr.color.grep=true; pdd @ sym.fnv1a32~:3..8");
    assert_eq!(piped(hashes(), &script).0, rows);
    let (plain, _) = piped(hashes(), "pdd @ sym.fnv1a32");
    let rows: String = plain
        .lines()
        .skip(3)
        .take(5)
        .map(|line| format!("{line}\n"))
        .collect();
    assert_eq!(
        piped(hashes(), &format!("{keys}; pdd @ sym.fnv1a32~:3..8")).0,
        rows
    );
    let (red, _) = piped(
        hashes(),
        "e scr.color.grep=true; ?e a\\e[31mred\\e[0m~red; e scr.color.grep",
    );
    assert_eq!(red, "a\x1b[31mred\x1b[0m\ntrue\n");
}
