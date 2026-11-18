//! `aoj` and `pdfj` carry each note `pdf` prints as typed fields (D582, doc/adr-display.md).

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
        let address = u64::from_str_radix(line.trim().get(2..10)?, 16).ok()?;
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

#[test]
fn every_aoj_note_is_the_pdf_note_of_its_line() {
    let rows: Value = serde_json::from_str(&piped("aoj 6 @ 0x08000040")).expect("aoj is JSON");
    let notes = (rows.as_array().expect("rows").iter())
        .map(|row| {
            let address = row["addr"].as_u64().expect("an address");
            let notes = row["notes"].as_array().expect("every row states its notes");
            (address, notes.iter().map(checked).collect::<Vec<_>>())
        })
        .collect::<Vec<_>>();
    assert_eq!(notes, listed());
}
