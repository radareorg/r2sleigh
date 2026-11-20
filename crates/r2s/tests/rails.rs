//! `pdd`'s rails and statement addresses (D568): a pipe gets the definition's bytes, and the laid
//! out text strips back to them.

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

/// A GCC-built x86-64 ELF carried in the tree, not stripped.
fn hashes() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/coverage/pinned/hashes_gcc_x64_O2")
}

/// The shell's stdout for `script`, run with stdout a pipe; it must succeed.
fn piped(script: &str) -> String {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(hashes())
        .env_remove("NO_COLOR")
        .output()
        .expect("the shell runs");
    assert!(done.status.success(), "{script}: {done:?}");
    String::from_utf8(done.stdout).expect("text")
}

/// Every function of hashes, by entry.
fn entries() -> Vec<String> {
    let listed = piped("afl");
    let words = listed
        .lines()
        .filter_map(|line| line.split_whitespace().next());
    words.map(str::to_owned).collect()
}

/// One command per function, split by a fence, in `entries` order.
fn each(command: &str) -> Vec<String> {
    let script = (entries().iter())
        .map(|entry| format!("?e ==F; {command} @ {entry}"))
        .collect::<Vec<_>>()
        .join("; ");
    let out = piped(&script);
    out.split("==F\n").skip(1).map(str::to_owned).collect()
}

/// A laid out line back to the definition's: the address column dropped, each `│   ` and a fold
/// `│ N> ` back to their indentation.
fn stripped(line: &str) -> (String, Option<u64>) {
    if line.trim().is_empty() {
        return (line.to_owned(), None);
    }
    let (column, rest) = line.split_at(11);
    let address = column
        .trim()
        .strip_prefix("0x")
        .map(|hex| u64::from_str_radix(hex, 16).expect("hex"));
    let mut rest = rest;
    let mut depth = 0;
    while let Some(after) = rest.strip_prefix("│   ") {
        depth += 1;
        rest = after;
    }
    if let Some(after) = rest.strip_prefix("│ ") {
        let (count, after) = after.split_once("> ").expect("a fold");
        depth = count.parse::<usize>().expect("a depth");
        rest = after;
    }
    (format!("{}{rest}", " ".repeat(depth * 4)), address)
}

/// A laid out continuation line's bytes: after the column and the rails, 4 cells more (D620).
fn continued(line: &str) -> Option<&str> {
    let mut rest = line.get(11..)?;
    while let Some(after) = rest.strip_prefix("│   ") {
        rest = after;
    }
    if let Some((_, after)) = rest
        .strip_prefix("│ ")
        .and_then(|after| after.split_once("> "))
    {
        rest = after;
    }
    rest.strip_prefix("    ")
}

/// In a pipe `asm.rails` and `asm.pdd.addr` are off, so `pdd` is the definition's bytes: the same
/// as with both keys set false.
#[test]
fn a_piped_pdd_is_the_definitions_bytes() {
    assert_eq!(piped("e asm.rails; e asm.pdd.addr"), "false\nfalse\n");
    assert_eq!(
        each("pdd"),
        each("e asm.rails=false; e asm.pdd.addr=false; pdd")
    );
}

/// With both keys the text strips back to the plain one, each address is a `pdf` line, and a
/// line is at most the column's 11 cells past its plain width.
#[test]
fn the_laid_out_pdd_strips_back_to_the_plain_one() {
    let plain = each("pdd");
    let laid = each("e asm.rails=true; e asm.pdd.addr=true; pdd");
    let listed = each("pdf");
    for ((plain, laid), listed) in plain.iter().zip(&laid).zip(&listed) {
        let instructions = (listed.lines())
            .filter_map(|line| line[line.find("0x")?..].split_whitespace().next())
            .filter_map(|word| u64::from_str_radix(word.strip_prefix("0x")?, 16).ok())
            .collect::<std::collections::BTreeSet<_>>();
        let mut back: Vec<String> = Vec::new();
        let mut widths: Vec<usize> = Vec::new();
        for line in laid.lines() {
            // A continuation is its statement's next bytes (D620).
            if let (Some(segment), Some(last), Some(width)) =
                (continued(line), back.last_mut(), widths.last_mut())
            {
                last.push_str(segment);
                *width = (*width).max(line.chars().count());
                continue;
            }
            let (back_line, address) = stripped(line);
            if let Some(address) = address {
                assert!(
                    instructions.contains(&address),
                    "{address:#x} is no line of pdf:\n{listed}"
                );
            }
            back.push(back_line);
            widths.push(line.chars().count());
        }
        let expected = plain.lines().map(str::to_owned).collect::<Vec<_>>();
        if let Some(at) = plain.lines().position(|line| line.contains("r2dec proof:")) {
            // The proof line gives way to its 0 to 2 lines in the mark grammar.
            // Only the proof line is replaced, so the lines it became are the count's difference.
            let notes = back.len() + 1 - expected.len();
            assert!(notes <= 2, "{laid}");
            back.splice(at..at + notes, [expected[at].clone()]);
            widths.splice(at..at + notes, [expected[at].chars().count()]);
        }
        assert_eq!(back, expected, "{laid}");
        for (laid, plain) in widths.into_iter().zip(&expected) {
            let plain = plain.chars().count();
            assert!(laid <= plain + 11, "{laid} > {plain} + 11");
        }
    }
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

/// Painted at any depth, the laid out text is the plain laid out text with escapes added.
#[test]
fn the_painted_layout_is_the_plain_layout() {
    let plain = piped("e asm.rails=true; e asm.pdd.addr=true; pdd @ sym.fnv1a32");
    for depth in 1..=3 {
        let script = format!(
            "e scr.color={depth}; e asm.rails=true; e asm.pdd.addr=true; pdd @ sym.fnv1a32"
        );
        let painted = piped(&script);
        assert!(painted.contains("\x1b["), "scr.color={depth}");
        assert_eq!(unpainted(&painted), plain, "scr.color={depth}");
    }
}

/// Each count of the plain proof line's type and unassigned clauses, as `N words`.
fn clause_counts(text: &str) -> Vec<String> {
    let Some(proof) = text.lines().find(|line| line.contains("r2dec proof:")) else {
        return Vec::new();
    };
    let words = [
        "data object type refused",
        "data object types refused",
        "never assigned",
        "held from entry",
    ];
    let clauses = proof.split("; ").filter_map(|clause| {
        let (count, rest) = clause.split_once(' ')?;
        count.parse::<usize>().ok()?;
        let said = words.iter().find(|said| rest.starts_with(**said))?;
        Some(format!("{count} {said}"))
    });
    clauses.collect()
}

/// The railed proof lines count every refused data object type and unassigned read the plain
/// proof line names (D621), read from the typed response, each under the refusal mark.
#[test]
fn the_railed_notes_count_the_proof_lines_type_clauses() {
    let plain = each("pdd");
    let laid = each("e asm.rails=true; pdd");
    let mut seen = 0;
    for (plain, laid) in plain.iter().zip(&laid) {
        let notes = (laid.lines())
            .find(|line| line.contains("/* "))
            .unwrap_or_default();
        for clause in clause_counts(plain) {
            assert!(notes.contains(&format!("! {clause}")), "{clause}:\n{laid}");
            seen += 1;
        }
    }
    assert!(seen > 0, "hashes states a type or unassigned clause");
}

/// On a terminal no laid out line passes 160 cells (D620), except where an `r2dec gap` comment,
/// which holds no break point, is the run past the room; the line without it fits.
#[test]
fn a_laid_out_line_fits_160_cells_or_holds_one_unbreakable_comment() {
    let laid = each("e asm.rails=true; e asm.pdd.addr=true; pdd");
    let mut over = Vec::new();
    for line in laid.iter().flat_map(|text| text.lines()) {
        let width = line.chars().count();
        if width <= 160 {
            continue;
        }
        let before = line
            .find("/* r2dec gap")
            .map(|at| line[..at].chars().count());
        if before.is_none_or(|before| before > 160) {
            over.push(format!("{width}: {line}"));
        }
    }
    assert!(
        over.is_empty(),
        "{} lines:\n{}",
        over.len(),
        over.join("\n")
    );
}
