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
    let mut parts = text.split('\x1b');
    let first = parts.next().unwrap_or_default().to_owned();
    parts.fold(first, |mut out, part| {
        out.push_str(part.split_once('m').map_or("", |(_, rest)| rest));
        out
    })
}

/// Plain mode (D581): a pipe gets no escape byte, and the text a terminal gets with its paint
/// removed; asking for colour still paints.
#[test]
fn a_piped_listing_is_the_painted_one_with_no_escape() {
    let plain = piped(hashes(), "pdf @ 0x401330");
    assert!(!plain.contains('\x1b'), "{plain}");
    assert!(plain.contains(" ; "), "the function has notes: {plain}");
    // The lanes and the rail are text too (D565): the `je` leaves, the loop's latch returns.
    assert!(
        plain.contains("┌─< 0x00401337") && plain.contains("─< 0x0040135a"),
        "{plain}"
    );
    for depth in 1..=3 {
        let painted = piped(hashes(), &format!("e scr.color={depth}; pdf @ 0x401330"));
        assert!(painted.contains('\x1b'), "{painted}");
        assert_eq!(unpainted(&painted), plain, "scr.color={depth}");
    }
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

/// For every function of hashes: `pdf` header, `afi` and `axt`, split by `?e` fences.
fn views() -> Vec<(String, String, String, String)> {
    let functions = piped(hashes(), "afl");
    let entries = (functions.lines())
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let script = (entries.iter())
        .map(|entry| format!("?e ==F; pdf @ {entry}; ?e ==A; afi @ {entry}; ?e ==X; axt @ {entry}"))
        .collect::<Vec<_>>()
        .join("; ");
    let out = piped(hashes(), &script);
    let parts = out.split("==F\n").skip(1).zip(entries);
    parts
        .map(|(part, entry)| {
            let (listing, rest) = part.split_once("==A\n").expect("afi follows pdf");
            let (info, references) = rest.split_once("==X\n").expect("axt follows afi");
            (
                entry,
                listing.to_owned(),
                info.to_owned(),
                references.to_owned(),
            )
        })
        .collect()
}

/// The header's notes and `afi`'s rows are one speller's: the same mark and words, and an
/// unproven result is never printed unmarked (D566).
#[test]
fn the_header_states_the_result_and_floor_afi_states() {
    let mut unproven = 0;
    for (entry, listing, info, _) in views() {
        let row = |key: &str| {
            info.lines()
                .find_map(|line| line.strip_prefix(key)?.split_once(" ; "))
                .map(|(_, note)| note.to_owned())
        };
        let note = |cell: char, prefix: &str| {
            let line = listing
                .lines()
                .find(|line| line.starts_with(&format!("│ ; {cell} {prefix}")));
            line.map(|line| line[format!("│ ; {cell} ").len()..].to_owned())
        };
        let result = row("result: unproven");
        let header = note('!', "result unproven: ");
        assert_eq!(
            result
                .as_ref()
                .map(|note| format!("! result unproven: {}", &note[2..])),
            header.map(|note| format!("! {note}")),
            "{entry}: {info}\n{listing}"
        );
        unproven += usize::from(result.is_some());
        assert_eq!(
            row("args: "),
            note('~', "at least ").map(|note| format!("~ {note}")),
            "{entry}"
        );
        assert!(
            !listing.contains("returns rax") || result.is_none(),
            "{entry}"
        );
    }
    assert!(unproven > 0, "hashes has an unproven result (`_init`)");
}

/// Each header xref is a row of `axt @ entry`, same caller and site; where `axt` lists a call the
/// header lacks, the `?` line says the list may be short.
#[test]
fn every_header_xref_is_a_row_of_axt() {
    let mut listed = 0;
    for (entry, listing, _, references) in views() {
        let rows = (references.lines())
            .filter_map(|line| {
                let mut words = line.split_whitespace();
                Some((
                    words.next()?.to_owned(),
                    words.next()?.to_owned(),
                    line.contains("[CALL"),
                ))
            })
            .collect::<Vec<_>>();
        let header = listing.lines().take_while(|line| line.starts_with(';'));
        let mut shown = 0;
        // `; XREFS(N)` folds the list past `asm.xrefs.fold`: it names no row.
        for line in header.filter(|line| line.contains(" from ")) {
            let (from, sites) = line
                .split_once(" from ")
                .expect("from")
                .1
                .split_once(" @ ")
                .expect("@");
            for site in sites.split(", ") {
                let site = site.trim_end_matches("(x)");
                let row = rows
                    .iter()
                    .any(|(caller, at, _)| caller == from && at == site);
                assert!(row, "{entry}: {line} is no row of axt:\n{references}");
                shown += 1;
            }
        }
        listed += shown;
        let calls = rows.iter().filter(|row| row.2).count();
        if calls > shown {
            assert!(
                listing.contains("; ? xrefs may be short"),
                "{entry}: {listing}"
            );
        }
    }
    assert!(listed > 0, "hashes' main calls each hash");
}

/// The header's count of unfollowed transfers is `axt`'s, both the survey's (D619).
#[test]
fn the_header_counts_the_unfollowed_transfers_axt_counts() {
    let number = |text: &str, after: &str, before: &str| {
        let line = text.lines().find(|line| line.contains(before))?;
        let words = line.split(before).next()?.rsplit(after).next()?;
        words.trim().parse::<usize>().ok()
    };
    for (entry, listing, _, references) in views() {
        let header = number(
            &listing,
            "xrefs may be short: ",
            " indirect transfers unresolved",
        );
        let axt = number(&references, "; ", " unresolved indirect transfer").or_else(|| {
            references
                .contains("every body walked to its end")
                .then_some(0)
        });
        assert_eq!(
            header.unwrap_or(0),
            axt.expect(&entry),
            "{entry}: {listing}\n{references}"
        );
        assert!(
            !listing.contains("indirect transfers unread"),
            "{entry}: every body is walked"
        );
    }
}
