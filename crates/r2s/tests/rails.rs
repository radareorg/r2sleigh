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
        let mut back = Vec::new();
        let mut widths = Vec::new();
        for line in laid.lines() {
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
