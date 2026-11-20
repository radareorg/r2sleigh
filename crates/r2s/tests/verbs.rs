//! D575's verbs whose answer needs logic: `ij` names the file it opened, so it is read as JSON.

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn hashes() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/coverage/pinned/hashes_gcc_x64_O2")
}

fn run(script: &str) -> (bool, String, String) {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(hashes())
        .output()
        .expect("the shell runs");
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    (
        done.status.success(),
        text(&done.stdout),
        text(&done.stderr),
    )
}

#[test]
fn ij_states_what_i_prints_under_radare2s_keys() {
    let (ok, out, err) = run("ij");
    assert!(ok, "{err}");
    let json: Value = serde_json::from_str(&out).expect("ij is JSON");
    assert_eq!(json["core"]["file"], hashes().to_str().expect("a path"));
    assert_eq!(json["core"]["format"], "elf64");
    let bin = &json["bin"];
    assert_eq!(bin["arch"], "x86-64");
    assert_eq!(bin["bits"], 64);
    assert_eq!(bin["endian"], "little");
    assert_eq!(bin["static"], false);
    // Each `ij` key holds what `i` prints in its row.
    let (_, info, _) = run("i");
    for key in [
        "arch", "bits", "endian", "lang", "nx", "pic", "relro", "static", "intrp",
    ] {
        let row = info
            .lines()
            .find(|line| line.split_whitespace().next() == Some(key));
        let printed = row.map(|row| row[9..].to_owned());
        let stated = bin.get(key).map(|value| match value {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        });
        assert_eq!(stated, printed, "{key}");
    }
}

#[test]
fn an_unknown_verb_fails_and_names_its_nearest_verb() {
    let (ok, out, err) = run("pdff");
    assert!(!ok);
    assert_eq!(out, "");
    assert_eq!(
        err.trim_end(),
        "r2s: unknown command 'pdff'; did you mean pdf"
    );
}
