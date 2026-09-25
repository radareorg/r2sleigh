//! `pddj`: one function's rendering as a translation unit a tool compiles,
//! with where each line came from and what every name in it is.
//!
//! Run as the shell, through `CARGO_BIN_EXE_r2s`, over every function
//! discovery finds, so the contract is checked where it is used rather than on
//! one function picked to pass.

#![cfg(feature = "sleigh")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// The stripped GCC fixture the repository ships as bytes: nothing names its
/// functions, so every one of them is found and rendered from the code alone.
fn stripped() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/hashes_gcc_x64_O2_stripped")
}

/// What the shell printed for one script, and whether it succeeded.
fn shell(binary: &Path, script: &str) -> (String, bool) {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(binary)
        .output()
        .expect("the shell runs");
    (
        String::from_utf8_lossy(&done.stdout).into_owned() + &String::from_utf8_lossy(&done.stderr),
        done.status.success(),
    )
}

/// Every function `afl` lists, by address.
fn functions(binary: &Path) -> Vec<u64> {
    let (out, ok) = shell(binary, "afl");
    assert!(ok, "{out}");
    out.lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|word| word.strip_prefix("0x"))
        .filter_map(|hex| u64::from_str_radix(hex, 16).ok())
        .collect()
}

/// The instruction starts `pdf` lists for the function at `addr`.
fn instructions(binary: &Path, addr: u64) -> BTreeSet<u64> {
    let (out, _) = shell(binary, &format!("pdf @ {addr:#x}"));
    out.lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|word| word.strip_prefix("0x"))
        .filter_map(|hex| u64::from_str_radix(hex, 16).ok())
        .collect()
}

/// A C compiler, where one is installed; the compile check is skipped without.
fn compiler() -> Option<&'static str> {
    ["cc", "gcc", "clang"].into_iter().find(|cc| {
        Command::new(cc)
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    })
}

/// Compile one unit as the contract says a consumer will: ISO C11, every
/// warning on, and a call to anything undeclared an error.
fn compile(cc: &str, code: &str, label: &str) {
    let dir = std::env::temp_dir().join(format!(
        "r2s-pddj-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("temporary directory");
    let source = dir.join("unit.c");
    std::fs::write(&source, code).expect("write the unit");
    let done = Command::new(cc)
        .args([
            "-std=c11",
            "-c",
            "-Wall",
            "-Werror=implicit-function-declaration",
            "-o",
        ])
        .arg(dir.join("unit.o"))
        .arg(&source)
        .output()
        .expect("run the compiler");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        done.status.success(),
        "{label} does not compile:\n{}\n{code}",
        String::from_utf8_lossy(&done.stderr)
    );
}

/// Check one answer against the contract and return it.
///
/// The proof's columns partition the obligations, so they sum to the total.
/// Every line is a line of the code and every address it names is an
/// instruction the function's own listing has. Every residual is written at
/// its site on its line, every link and variable is a name the code spells,
/// and a unit that defines the function carries its header.
fn checked(binary: &Path, addr: u64, cc: Option<&str>) -> Value {
    let (out, ok) = shell(binary, &format!("pddj @ {addr:#x}"));
    assert!(ok, "{addr:#x}: {out}");
    let answer: Value = serde_json::from_str(out.trim()).unwrap_or_else(|error| {
        panic!("{addr:#x}: not one JSON object ({error}): {out}");
    });
    let label = format!("{addr:#x} ({})", answer["name"]);
    assert_eq!(answer["addr"].as_u64(), Some(addr), "{label}");
    let code = answer["code"].as_str().expect("code is text");
    let text = code.lines().collect::<Vec<_>>();

    let proof = &answer["proof"];
    let columns = [
        "rendered",
        "elided",
        "refused",
        "residual",
        "split",
        "compiler_inserted",
        "assumed",
        "unaccounted",
    ]
    .into_iter()
    .map(|column| {
        proof[column]
            .as_u64()
            .unwrap_or_else(|| panic!("{label}: proof.{column} missing: {proof}"))
    })
    .sum::<u64>();
    assert_eq!(Some(columns), proof["total"].as_u64(), "{label}: {proof}");
    // A residual stands in for some obligation, and an obligation counted as
    // residual has one standing in for it: a function whose text traps
    // never reads as fully proven, and one that reads unproven shows where.
    let residuals = answer["residuals"].as_array().expect("residuals");
    assert_eq!(
        proof["residual"].as_u64() == Some(0),
        residuals.is_empty(),
        "{label}: {proof} beside {} residual sites",
        residuals.len()
    );

    let listed = instructions(binary, addr);
    for line in answer["lines"].as_array().expect("lines") {
        let at = line["line"].as_u64().expect("a line number");
        assert!(
            (1..=text.len() as u64).contains(&at),
            "{label}: line {at} of {}",
            text.len()
        );
        for address in line["addrs"].as_array().expect("addresses") {
            let address = address.as_u64().expect("an address");
            assert!(
                listed.contains(&address),
                "{label}: line {at} names {address:#x}, which the listing does not have"
            );
        }
    }
    for residual in answer["residuals"].as_array().expect("residuals") {
        let at = residual["line"].as_u64().expect("a line") as usize;
        let call = format!(
            "r2sleigh_residual_{}({})",
            residual["type"].as_str().expect("a type"),
            residual["site"]
        );
        assert!(
            text.get(at - 1).is_some_and(|line| line.contains(&call)),
            "{label}: {call} is not on line {at}"
        );
        // Each site says why it is unproven; a gap also names its marker's
        // kind, which the comment after it spells.
        let cause = residual["cause"].as_str().expect("a cause");
        assert!(
            [
                "unproven-return",
                "held-from-entry",
                "unadmitted-argument",
                "never-assigned",
                "unrepresentable-float",
                "gap",
            ]
            .contains(&cause),
            "{label}: {call} has cause {cause}"
        );
        if cause == "gap" {
            let kind = residual["gap"].as_str().expect("a gap's kind");
            assert!(
                text[at - 1].contains(&format!("r2dec gap: {kind} ")),
                "{label}: {call} is a {kind} gap"
            );
        }
    }
    for link in answer["links"].as_array().expect("links") {
        let ident = link["ident"].as_str().expect("an identifier");
        assert!(
            code.contains(ident),
            "{label}: link {ident} is not in the code"
        );
    }
    for variable in answer["variables"].as_array().expect("variables") {
        let name = variable["name"].as_str().expect("a name");
        assert!(
            code.contains(name),
            "{label}: variable {name} is not in the code"
        );
    }
    match &answer["refused"] {
        Value::Null => {
            let signature = answer["signature"].as_str().expect("a signature");
            assert!(code.contains(signature), "{label}: {signature}");
            let definition = answer["definition"].as_str().expect("a definition");
            assert!(signature.contains(definition), "{label}: {signature}");
            // The header is C: it names a type before the function, never a
            // comment where a type should be.
            assert!(!signature.starts_with("/*"), "{label}: {signature}");
        }
        refused => assert!(refused["reason"].is_string(), "{label}: {refused}"),
    }
    if let Some(cc) = cc {
        compile(cc, code, &label);
    }
    answer
}

#[test]
fn every_function_is_a_unit_that_compiles_and_accounts_for_itself() {
    let binary = stripped();
    let cc = compiler();
    let found = functions(&binary);
    assert!(found.len() > 4, "{found:?}");
    let mut defined = 0;
    for addr in found {
        let answer = checked(&binary, addr, cc);
        defined += usize::from(answer["refused"].is_null());
    }
    // A stripped binary still has functions whose bodies render.
    assert!(defined > 4, "{defined} defined");
}

#[test]
fn an_unmapped_address_has_no_answer() {
    let (out, ok) = shell(&stripped(), "pddj @ 0x999999");
    assert!(!ok, "{out}");
}

/// The review fixtures, named by `R2S_REVIEW_FIXTURES`: a directory holding
/// `rv_O0g` (gcc -O0 -g) and `rv_O2` (gcc -O2) built from `review.c`. Skipped
/// when unset, since the binaries are not in the tree.
#[test]
fn the_review_fixtures_are_units_that_compile() {
    let Some(dir) = std::env::var_os("R2S_REVIEW_FIXTURES").map(PathBuf::from) else {
        return;
    };
    let cc = compiler();
    // Every function is checked and every failure reported, so one function
    // that does not answer does not hide the rest.
    let mut failures = Vec::new();
    let mut dispatch_at_o0 = false;
    for build in ["rv_O0g", "rv_O2"] {
        let binary = dir.join(build);
        for addr in functions(&binary) {
            let answer = match std::panic::catch_unwind(|| checked(&binary, addr, cc)) {
                Ok(answer) => answer,
                Err(cause) => {
                    let cause = cause
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| cause.downcast_ref::<&str>().map(|text| (*text).to_owned()))
                        .unwrap_or_default();
                    failures.push(format!("{build} {addr:#x}: {cause}"));
                    continue;
                }
            };
            // `dispatch` returns what a function pointer it was handed
            // returns, which nothing proves. At -O0 it renders, and its header
            // states the result carrier and every return is a residual of it.
            if build == "rv_O0g" && answer["definition"] == "dispatch" {
                dispatch_at_o0 = true;
                let signature = answer["signature"].as_str().unwrap_or_default();
                let returns_residual = answer["residuals"].as_array().is_some_and(|sites| {
                    sites
                        .iter()
                        .any(|site| site["cause"] == "unproven-return" && site["type"] == "u64")
                });
                if !signature.starts_with("uint64_t dispatch(")
                    || !answer["code"]
                        .as_str()
                        .is_some_and(|code| code.contains("return r2sleigh_residual_u64("))
                    || !returns_residual
                    || answer["proof"]["residual"].as_u64() == Some(0)
                {
                    failures.push(format!("{build} dispatch: {answer}"));
                }
            }
        }
    }
    assert!(dispatch_at_o0, "rv_O0g has no dispatch");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
