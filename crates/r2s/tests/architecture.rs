//! The boundaries the shell is held to, checked against the source.
//!
//! `r2s` is a client of one typed surface. It lays out columns; it does not
//! decode, it does not read the container itself, and it does not parse
//! anything the engine formatted, because the engine formats nothing.

use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root is reachable from the crate")
}

fn sources(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(at) = pending.pop() {
        for entry in fs::read_dir(&at).expect("the source directory exists") {
            let path = entry.expect("the entry is readable").path();
            match path.is_dir() {
                true => pending.push(path),
                false if path.extension().is_some_and(|kind| kind == "rs") => found.push(path),
                false => {}
            }
        }
    }
    found.sort();
    found
}

/// Every line of a crate's sources that mentions one of `wanted`.
fn mentions(dir: &Path, wanted: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    for file in sources(dir) {
        let text = fs::read_to_string(&file).expect("the source is UTF-8");
        let name = file
            .file_name()
            .expect("a source file has a name")
            .to_string_lossy()
            .into_owned();
        for (index, line) in text.lines().enumerate() {
            if wanted.iter().any(|needle| line.contains(needle)) {
                found.push(format!("{name}:{} {}", index + 1, line.trim()));
            }
        }
    }
    found
}

#[test]
fn the_shell_depends_on_the_engine_and_nothing_else() {
    let manifest =
        fs::read_to_string(root().join("crates/r2s/Cargo.toml")).expect("the shell has a manifest");
    let dependencies = manifest
        .split("[dependencies]")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .expect("the manifest declares dependencies");
    let others: Vec<&str> = dependencies
        .lines()
        .filter(|line| line.starts_with("r2") && !line.starts_with("r2engine"))
        .collect();
    assert!(
        others.is_empty(),
        "the shell reaches past the engine:\n{}",
        others.join("\n")
    );
}

#[test]
fn the_shell_names_no_crate_but_the_engine() {
    let reaching = mentions(
        &root().join("crates/r2s/src"),
        &[
            "r2image::",
            "r2il::",
            "r2ssa::",
            "r2abi::",
            "r2sleigh_lift::",
        ],
    );
    assert!(
        reaching.is_empty(),
        "the shell names a crate the engine owns:\n{}",
        reaching.join("\n")
    );
}

#[test]
fn the_shell_never_decodes() {
    let decoding = mentions(
        &root().join("crates/r2s/src"),
        &["disasm_native", "disasm_syntax", "Disassembler", ".lift("],
    );
    assert!(
        decoding.is_empty(),
        "the shell decodes instead of asking the engine:\n{}",
        decoding.join("\n")
    );
}

#[test]
fn the_query_surface_formats_nothing() {
    let formatting = mentions(
        &root().join("crates/r2engine/src/query"),
        &["format!", "write!", "push_str"],
    );
    let outside_tests: Vec<String> = formatting
        .into_iter()
        .filter(|line| !line.contains("assert"))
        .collect();
    assert!(
        outside_tests.is_empty(),
        "the query surface returns records, not text:\n{}",
        outside_tests.join("\n")
    );
}
