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
    check_proof(&label, &answer);
    check_lines(&label, &answer, &text, &instructions(binary, addr));
    for residual in answer["residuals"].as_array().expect("residuals") {
        check_residual(&label, residual, &text);
    }
    check_names(&label, &answer, code);
    check_definition(&label, &answer, code);
    if let Some(cc) = cc {
        compile(cc, code, &label);
    }
    answer
}

/// The proof's columns partition the total, and it counts residual
/// obligations exactly when the unit holds a residual site.
///
/// A residual stands in for some obligation, and an obligation counted as
/// residual has one standing in for it: a function whose text traps never
/// reads as fully proven, and one that reads unproven shows where.
fn check_proof(label: &str, answer: &Value) {
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
    let residuals = answer["residuals"].as_array().expect("residuals");
    assert_eq!(
        proof["residual"].as_u64() == Some(0),
        residuals.is_empty(),
        "{label}: {proof} beside {} residual sites",
        residuals.len()
    );
}

/// Every line is a line of the code, and every address it names is an
/// instruction the function's own listing has.
fn check_lines(label: &str, answer: &Value, text: &[&str], listed: &BTreeSet<u64>) {
    for line in answer["lines"].as_array().expect("lines") {
        let at = line["line"].as_u64().expect("a line number");
        assert!(
            (1..=text.len() as u64).contains(&at),
            "{label}: line {at} of {}",
            text.len()
        );
        let addresses = line["addrs"].as_array().expect("addresses");
        let foreign = addresses
            .iter()
            .map(|address| address.as_u64().expect("an address"))
            .find(|address| !listed.contains(address));
        assert_eq!(
            foreign, None,
            "{label}: line {at} names an address the listing does not have"
        );
    }
}

/// The causes a residual site may state.
const CAUSES: [&str; 6] = [
    "unproven-return",
    "held-from-entry",
    "unadmitted-argument",
    "never-assigned",
    "unrepresentable-float",
    "gap",
];

/// A residual is written at its site on its line, and says why it is
/// unproven; a gap also names its marker's kind, which the comment after it
/// spells.
fn check_residual(label: &str, residual: &Value, text: &[&str]) {
    let at = residual["line"].as_u64().expect("a line") as usize;
    let call = format!(
        "r2sleigh_residual_{}({})",
        residual["type"].as_str().expect("a type"),
        residual["site"]
    );
    let line = text.get(at - 1).copied().unwrap_or_default();
    assert!(line.contains(&call), "{label}: {call} is not on line {at}");
    let cause = residual["cause"].as_str().expect("a cause");
    assert!(CAUSES.contains(&cause), "{label}: {call} has cause {cause}");
    if cause == "gap" {
        let kind = residual["gap"].as_str().expect("a gap's kind");
        assert!(
            line.contains(&format!("r2dec gap: {kind} ")),
            "{label}: {call} is a {kind} gap"
        );
    }
}

/// Every link and every variable is a name the code spells.
fn check_names(label: &str, answer: &Value, code: &str) {
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
}

/// A unit that defines the function carries its header, which is C; one that
/// refuses says why, whichever layer refused.
fn check_definition(label: &str, answer: &Value, code: &str) {
    let refused = &answer["refused"];
    if !refused.is_null() {
        assert!(
            refused["reason"]
                .as_str()
                .is_some_and(|reason| !reason.trim().is_empty()),
            "{label}: {refused}"
        );
        return;
    }
    let signature = answer["signature"].as_str().expect("a signature");
    assert!(code.contains(signature), "{label}: {signature}");
    let definition = answer["definition"].as_str().expect("a definition");
    assert!(signature.contains(definition), "{label}: {signature}");
    // The header is C: it names a type before the function, never a comment
    // where a type should be.
    assert!(!signature.starts_with("/*"), "{label}: {signature}");
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

/// Whether `dispatch` at -O0 marks its return unproven as the contract says.
///
/// It returns what a function pointer it was handed returns, which nothing
/// proves. Its header states the result carrier, every return is a residual
/// of it whose cause is the unproven return, and the proof counts it.
fn dispatch_marks_its_unproven_return(answer: &Value) -> bool {
    let signature = answer["signature"].as_str().unwrap_or_default();
    let code = answer["code"].as_str().unwrap_or_default();
    let sites = answer["residuals"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let returns_residual = sites
        .iter()
        .any(|site| site["cause"] == "unproven-return" && site["type"] == "u64");
    signature.starts_with("uint64_t dispatch(")
        && code.contains("return r2sleigh_residual_u64(")
        && returns_residual
        && answer["proof"]["residual"].as_u64() != Some(0)
}

/// What a caught panic said.
fn panic_text(cause: &(dyn std::any::Any + Send)) -> String {
    cause
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| cause.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_default()
}

/// GCC, where it is installed. Its flow-sensitive uninitialized-read
/// analysis is the judge of definite assignment that owes the engine nothing;
/// clang's does not follow values through the optimizer, so it cannot stand
/// in for it.
fn gcc() -> Option<&'static str> {
    ["gcc", "cc"].into_iter().find(|cc| {
        Command::new(cc)
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success() && out.stdout.starts_with(cc.as_bytes()))
    })
}

/// Whether a unit reads no variable before assigning it, as GCC judges it
/// with the optimizer's dataflow on: at `-O2` with every uninitialized and
/// maybe-uninitialized read an error. A read the engine cannot prove assigned
/// is a residual, which is a call and reads nothing; a declared name read on
/// a path that never assigned it is an indeterminate value, and C gives that
/// no meaning.
fn definitely_assigned(gcc: &str, code: &str, label: &str) -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!(
        "r2s-pddj-assigned-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("temporary directory");
    let source = dir.join("unit.c");
    std::fs::write(&source, code).expect("write the unit");
    let done = Command::new(gcc)
        .args([
            "-std=c11",
            "-O2",
            "-c",
            "-Wall",
            "-Werror=implicit-function-declaration",
            "-Werror=uninitialized",
            "-Werror=maybe-uninitialized",
            "-o",
        ])
        .arg(dir.join("unit.o"))
        .arg(&source)
        .output()
        .expect("run the compiler");
    let _ = std::fs::remove_dir_all(&dir);
    if done.status.success() {
        return Ok(());
    }
    Err(format!(
        "{label} reads a name it never assigned:\n{}",
        String::from_utf8_lossy(&done.stderr)
    ))
}

/// The causes of an answer's residual sites, in site order.
fn causes(answer: &Value) -> Vec<&str> {
    answer["residuals"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|site| site["cause"].as_str())
        .collect()
}

/// What the review fixture at -O2 must say where a read has no assignment,
/// or `None` when it says it.
///
/// `sext` merges the byte it sign-extends into the entry value of `rax`, which
/// the caller never supplied: that read is held from entry. `main` reads
/// `avg`'s floating-point result in `xmm0` after a call whose prototype claims
/// no such result, so nothing assigned it. Both canary loads read the one
/// thread pointer `main` entered with, which C has no name for, and no call
/// redefines it.
fn unassigned_reads_at_o2(definition: &str, answer: &Value) -> Option<String> {
    let code = answer["code"].as_str().unwrap_or_default();
    let causes = causes(answer);
    let (expected, said) = if definition == "sext" {
        (
            vec!["held-from-entry"],
            code.contains("1 held from entry, read as residuals (RAX_0)"),
        )
    } else {
        (
            vec!["held-from-entry", "never-assigned", "held-from-entry"],
            code.contains("1 held from entry, read as residuals (FS_OFFSET_0)")
                && code.contains("1 never assigned, read as residuals (XMM0_4)")
                && !code.contains("FS_OFFSET_15"),
        )
    };
    (causes != expected || !said).then(|| format!("rv_O2 {definition}: {causes:?}\n{code}"))
}

/// The review fixtures the repository ships: `rv_O0g` (gcc -O0 -g) and
/// `rv_O2` (gcc -O2), both built from `tests/gold/review.c`.
///
/// Every function is a unit that compiles, and, where GCC is installed, one
/// that reads no name it did not assign.
#[test]
fn the_review_fixtures_are_units_that_compile() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let cc = compiler();
    let gcc = gcc();
    // Every function is checked and every failure reported, so one function
    // that does not answer does not hide the rest.
    let mut failures = Vec::new();
    let mut dispatch_at_o0 = false;
    let mut split_at_o0 = false;
    let mut judged_at_o2 = BTreeSet::new();
    for build in ["rv_O0g", "rv_O2"] {
        let binary = fixtures.join(build);
        for addr in functions(&binary) {
            let answer = match std::panic::catch_unwind(|| checked(&binary, addr, cc)) {
                Ok(answer) => answer,
                Err(cause) => {
                    failures.push(format!("{build} {addr:#x}: {}", panic_text(&*cause)));
                    continue;
                }
            };
            let label = format!("{build} {addr:#x} ({})", answer["name"]);
            let code = answer["code"].as_str().unwrap_or_default();
            if let Some(gcc) = gcc
                && let Err(failure) = definitely_assigned(gcc, code, &label)
            {
                failures.push(failure);
            }
            let definition = answer["definition"].as_str().unwrap_or_default();
            if build == "rv_O2" && matches!(definition, "sext" | "main") {
                judged_at_o2.insert(definition.to_owned());
                failures.extend(unassigned_reads_at_o2(definition, &answer));
            }
            // `mul_div` reloads `a` for its second division after `cqo` has
            // written the first reload's sign into the variable `a` shares;
            // the reload is read through a variable of its own, and the proof
            // counts what that split renders.
            if build == "rv_O0g" && definition == "mul_div" {
                split_at_o0 = true;
                if answer["proof"]["split"].as_u64().unwrap_or_default() == 0 {
                    failures.push(format!("{build} mul_div splits nothing: {answer}"));
                }
            }
            if build == "rv_O0g" && definition == "dispatch" {
                dispatch_at_o0 = true;
                if !dispatch_marks_its_unproven_return(&answer) {
                    failures.push(format!("{build} dispatch: {answer}"));
                }
            }
        }
    }
    assert!(dispatch_at_o0, "rv_O0g has no dispatch");
    assert!(split_at_o0, "rv_O0g has no mul_div");
    assert_eq!(
        judged_at_o2,
        BTreeSet::from(["main".to_owned(), "sext".to_owned()]),
        "rv_O2 lacks a function whose unassigned reads are named"
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
