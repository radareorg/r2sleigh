//! `pdfj` carries each note `pdf` prints as typed fields (D582, doc/adr-display.md).

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

/// An x86-64 relocatable object whose `f` calls an undeclared import and a function of its own.
fn relocated() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../r2image/tests/data/relocated.elf")
}

/// The shell's stdout for `script`, run with stdout a pipe.
fn piped(script: &str) -> String {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(relocated())
        .output()
        .expect("the shell runs");
    assert!(done.status.success(), "{script}: {done:?}");
    String::from_utf8(done.stdout).expect("the answer is text")
}

/// Every note's fields, checked against the one schema: a refusal states no basis, grade or
/// premise, and a fact states its basis and grade.
fn checked(note: &Value) -> (String, String) {
    let fields = note.as_object().expect("a note is an object");
    let keys = fields.keys().map(String::as_str).collect::<Vec<_>>();
    let expected = [
        "basis", "citation", "grade", "kind", "mark", "premises", "refusal", "text",
    ];
    assert_eq!(keys, expected, "{note}");
    let mark = note["mark"].as_str().expect("a mark");
    assert_eq!(mark.chars().count(), 1, "{note}");
    assert!(note["premises"].is_array(), "{note}");
    match note["refusal"].is_null() {
        true => {
            assert!(
                note["basis"].is_string() && note["grade"].is_string(),
                "{note}"
            );
        }
        false => {
            assert!(note["basis"].is_null() && note["grade"].is_null(), "{note}");
            assert!(note["refusal"]["reason"].is_string(), "{note}");
        }
    }
    let text = note["text"].as_str().expect("a text").to_owned();
    (mark.to_owned(), text)
}

/// Each `pdf` line's notes as `(mark cell, text)`, in order.
fn listed() -> Vec<(u64, Vec<(String, String)>)> {
    let listing = piped("pdf @ 0x08000040");
    let parsed = listing.lines().filter_map(|line| {
        // An instruction row: only the rail and flow lanes before its address.
        let at = line.find("0x")?;
        let gutter = &line[..at];
        if gutter
            .chars()
            .any(|cell| cell.is_alphanumeric() || cell == ';')
        {
            return None;
        }
        let address = u64::from_str_radix(line.get(at + 2..at + 10)?, 16).ok()?;
        let notes = (line.split(" ; ").skip(1))
            .map(|note| (note[..1].to_owned(), note[2..].to_owned()))
            .collect();
        Some((address, notes))
    });
    parsed.collect()
}

#[test]
fn every_pdfj_note_is_the_pdf_note_with_its_standing_as_fields() {
    let json: Value = serde_json::from_str(&piped("pdfj @ 0x08000040")).expect("pdfj is JSON");
    assert_eq!(json["addr"], 0x0800_0040_u64);
    assert_eq!(json["name"], "sym.f");
    let lines = json["lines"].as_array().expect("lines");
    let notes = (lines.iter())
        .map(|line| {
            let address = line["addr"].as_u64().expect("an address");
            let notes = line["notes"].as_array().expect("notes");
            (address, notes.iter().map(checked).collect::<Vec<_>>())
        })
        .collect::<Vec<_>>();
    assert_eq!(notes, listed());
    let refused = notes
        .iter()
        .flat_map(|(_, notes)| notes)
        .filter(|(mark, _)| mark == "!");
    assert_eq!(refused.count(), 2, "{notes:?}");
}

/// gcc -O2 hashes, unstripped: its functions' calls carry argument and `noreturn` notes.
fn hashes() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/coverage/pinned/hashes_gcc_x64_O2")
}

/// The shell's stdout for `script` over hashes.
fn hashes_piped(script: &str) -> String {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(hashes())
        .output()
        .expect("the shell runs");
    assert!(done.status.success(), "{script}: {done:?}");
    String::from_utf8(done.stdout).expect("the answer is text")
}

/// The notes of the listing row at `address`, as `(mark cell, text)`.
fn row_notes(listing: &str, address: u64) -> Vec<(String, String)> {
    let spelled = format!("{address:#010x}");
    let row = (listing.lines())
        .find(|line| line.trim_start().starts_with(&spelled))
        .unwrap_or_else(|| panic!("no row at {spelled} in {listing}"));
    (row.split(" ; ").skip(1))
        .map(|note| (note[..1].to_owned(), note[2..].to_owned()))
        .collect()
}

/// A note's mark cell and text; an unknown states no basis, as a refusal does not.
fn cell_and_text(note: &Value) -> (String, String) {
    let mark = note["mark"].as_str().expect("a mark").to_owned();
    assert!(
        note["premises"].is_array() && note["kind"].is_string(),
        "{note}"
    );
    (mark, note["text"].as_str().expect("a text").to_owned())
}

#[test]
fn every_aoj_note_is_the_note_pd_prints_on_its_line() {
    let entry = 0x0040_1050_u64;
    let json: Value =
        serde_json::from_str(&hashes_piped(&format!("pdfj @ {entry:#x}"))).expect("pdfj");
    let addresses = (json["lines"].as_array().expect("lines").iter())
        .map(|line| line["addr"].as_u64().expect("an address"))
        .collect::<Vec<_>>();
    assert!(addresses.len() > 8, "{json}");
    // One instruction at a time: `aoj 1` against `pd 1` at each address.
    let script = (addresses.iter())
        .map(|at| format!("pd 1 @ {at:#x}; aoj 1 @ {at:#x}"))
        .collect::<Vec<_>>()
        .join("; ");
    let out = hashes_piped(&script);
    let mut blocks = out
        .split_inclusive('\n')
        .fold(vec![String::new()], |mut blocks, line| {
            blocks.last_mut().expect("a block").push_str(line);
            if line.starts_with('[') {
                blocks.push(String::new());
            }
            blocks
        });
    blocks.pop();
    assert_eq!(blocks.len(), addresses.len());
    let mut noted = 0;
    for (at, block) in addresses.iter().zip(&blocks) {
        let (listing, aoj) = block.trim_end().rsplit_once('\n').expect("pd then aoj");
        let aoj: Value = serde_json::from_str(aoj).expect("aoj is JSON");
        let notes = aoj[0]["notes"].as_array().expect("aoj carries notes");
        let notes = notes.iter().map(cell_and_text).collect::<Vec<_>>();
        noted += notes.len();
        assert_eq!(notes, row_notes(listing, *at), "{at:#x}");
    }
    assert!(noted > 0, "no note in {entry:#x}");
    // A run: each line's notes as `pd n` prints them, its next call in the run included.
    let listing = hashes_piped(&format!("pd 40 @ {entry:#x}"));
    let run: Value =
        serde_json::from_str(&hashes_piped(&format!("aoj 40 @ {entry:#x}"))).expect("aoj");
    for one in run.as_array().expect("rows") {
        let at = one["addr"].as_u64().expect("an address");
        let notes = one["notes"].as_array().expect("aoj carries notes");
        let notes = notes.iter().map(cell_and_text).collect::<Vec<_>>();
        assert_eq!(notes, row_notes(&listing, at), "{at:#x} in a run");
    }
}
