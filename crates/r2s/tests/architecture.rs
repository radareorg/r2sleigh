//! The boundaries the shell is held to, checked against the source.
//!
//! `r2s` opens the binary and spells the answer. It hands the engine the bytes
//! and what the container states, and reads back records; it does not decode,
//! it does not derive, and it does not parse anything the engine formatted,
//! because the engine formats nothing.

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

/// What the shell may be built against: the engine it asks, and the container
/// parser it opens with. What the container states reaches the engine in the
/// loader's own types, so the shell has no word of its own to translate into.
const SHELL_MAY_REACH: [&str; 2] = ["r2engine", "r2image"];

#[test]
fn a_container_statement_type_has_one_definition() {
    // The loader, the engine and the shell each defined their own sections,
    // symbols and relocations, and the shell copied the first into the second
    // field by field, so every fact added to the loader was silently narrowed
    // away unless someone added it in three places. They are `r2abi`'s.
    let restated = ["r2image", "r2engine", "r2s"]
        .iter()
        .flat_map(|krate| {
            mentions(
                &root().join("crates").join(krate).join("src"),
                &[
                    "pub struct Section ",
                    "pub struct Segment ",
                    "pub struct Symbol ",
                    "pub enum SymbolKind",
                    "pub struct Relocation ",
                    "pub struct Entry ",
                    "pub struct EntryPoint",
                    "pub enum EntryKind",
                    "pub struct Permissions",
                    "pub struct Container ",
                ],
            )
        })
        .collect::<Vec<_>>();
    assert!(
        restated.is_empty(),
        "a container statement is defined again outside r2abi::statement:\n{}",
        restated.join("\n")
    );
}

#[test]
fn how_far_a_derived_fact_is_trusted_has_one_definition() {
    // Discovery defined its own confidence, so the first inferred fact the
    // engine produced said how far it could be trusted in a word no other
    // fact could use. It is `r2source`'s, with the premises a fact assumes,
    // and every crate that derives a fact states its trust in it.
    let restated = ["r2engine", "r2s", "r2ssa", "r2types", "r2dec", "r2image"]
        .iter()
        .flat_map(|krate| {
            mentions(
                &root().join("crates").join(krate).join("src"),
                &[
                    "pub enum Confidence",
                    "pub struct Confidence",
                    "pub enum Basis",
                    "pub enum Premise",
                ],
            )
        })
        .collect::<Vec<_>>();
    assert!(
        restated.is_empty(),
        "a confidence is defined again outside r2source::confidence:\n{}",
        restated.join("\n")
    );
}

#[test]
fn the_shell_depends_on_the_engine_and_the_container_only() {
    // Asked of the resolved dependency graph rather than of the manifest text.
    // Reading the manifest said what was written down; this says what the
    // shell is actually built against, which is the thing being held to. The
    // first attempt read the metadata as text and passed while `r2il` was a
    // declared dependency, which is exactly the failure this replaces.
    let metadata = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(root())
        .output()
        .expect("cargo metadata runs");
    let workspace: serde_json::Value =
        serde_json::from_slice(&metadata.stdout).expect("cargo metadata is JSON");
    let shell = workspace["packages"]
        .as_array()
        .expect("the metadata lists packages")
        .iter()
        .find(|package| package["name"] == "r2s")
        .expect("the workspace holds the shell");
    let reached: Vec<&str> = shell["dependencies"]
        .as_array()
        .expect("the shell declares dependencies")
        .iter()
        // A test may reach for anything; this is about what the shell is.
        .filter(|dependency| dependency["kind"].is_null())
        .filter_map(|dependency| dependency["name"].as_str())
        .filter(|name| name.starts_with("r2") && !SHELL_MAY_REACH.contains(name))
        .collect();
    assert!(
        reached.is_empty(),
        "the shell is built against crates the engine owns: {reached:?}"
    );
}

#[test]
fn the_shell_names_no_crate_the_engine_owns() {
    let reaching = mentions(
        &root().join("crates/r2s/src"),
        &[
            "r2ssa::",
            "r2abi::",
            "r2sleigh_lift::",
            "r2dec::",
            "r2types::",
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

#[test]
fn the_shell_sequences_no_analysis() {
    // Which tables are current, which machine is assembled, what is prepared
    // before what is rendered, and where discovery starts: the engine's order
    // to keep, asked for in one call.
    let sequencing = mentions(
        &root().join("crates/r2s/src"),
        &[
            "NativeTarget",
            "r2engine::native::",
            "discovery::functions",
            "ensure_assembled",
        ],
    );
    assert!(
        sequencing.is_empty(),
        "the shell sequences the engine's work:\n{}",
        sequencing.join("\n")
    );
}
