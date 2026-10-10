//! The staged proof line counts a residual only where its text holds a site for it: a residual
//! call or a marked gap. Checked over every function of two fixtures, as `census.py sites` checks
//! the whole census.

#![cfg(feature = "sleigh")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn binary(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn shell(binary: &Path, script: &str) -> String {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(binary)
        .output()
        .expect("the shell runs");
    String::from_utf8_lossy(&done.stdout).into_owned() + &String::from_utf8_lossy(&done.stderr)
}

/// The number written before `noun` in `text`, or 0.
fn column(text: &str, noun: &str) -> usize {
    let words = text.split([' ', ',', ';']).collect::<Vec<_>>();
    words
        .windows(2)
        .find(|pair| pair[1] == noun)
        .and_then(|pair| pair[0].parse().ok())
        .unwrap_or(0)
}

/// Why `rendered`'s proof line counts what its text does not hold; empty when it agrees.
fn mismatches(rendered: &str) -> Vec<String> {
    let mut wrong = Vec::new();
    if rendered.contains("unaccounted") {
        wrong.push("an unaccounted obligation".to_owned());
    }
    let Some(at) = rendered.find("r2dec proof:") else {
        return wrong;
    };
    let line = &rendered[at..rendered[at..]
        .find("*/")
        .map_or(rendered.len(), |end| at + end)];
    let body = &rendered[at + line.len()..];
    let sites = body.matches("r2sleigh_residual_").count();
    let marked = (line.split_whitespace().nth(2))
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(0);
    let unnamed = column(line, "residual");
    if unnamed > 0 && sites == 0 {
        wrong.push(format!("{unnamed} residual, no site"));
    }
    if marked != sites {
        wrong.push(format!("{marked} marked, {sites} in the text"));
    }
    wrong
}

fn assert_sited(path: &str) {
    let binary = binary(path);
    let listing = shell(&binary, "afl");
    let addresses = listing
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|word| word.starts_with("0x"))
        .collect::<Vec<_>>();
    assert!(!addresses.is_empty(), "{listing}");
    let wrong = addresses
        .iter()
        .flat_map(|addr| {
            let rendered = shell(&binary, &format!("pdd @ {addr}"));
            mismatches(&rendered)
                .into_iter()
                .map(move |why| format!("{addr}: {why}"))
        })
        .collect::<Vec<_>>();
    assert!(wrong.is_empty(), "{path}: {wrong:#?}");
}

/// rv_O0g, whose private frame reads nothing observes owe no obligation (r2ssa's seeding): every
/// residual its proof lines count has a site, with no exception named.
#[test]
fn every_counted_residual_has_its_site_on_rv_o0g() {
    assert_sited("tests/fixtures/rv_O0g");
}

/// RISC-V prologue adds (frame setup) and canary addresses were counted with no site.
#[test]
fn every_counted_residual_has_its_site_on_riscv() {
    assert_sited("tests/fixtures/shapes_zig_riscv64_O0");
}

/// x86-64: control residuals, a return's and a trap's, and the gap a `_start` call leaves.
#[test]
fn every_counted_residual_has_its_site_on_x86_64() {
    assert_sited("tests/coverage/pinned/branchy_gcc_x64_O0");
}

#[test]
fn the_check_reads_a_hidden_residual_as_a_mismatch() {
    let hidden = "/* r2dec proof: no individual construct is marked; 9 source obligations: \
                  7 rendered, 0 elided, 0 refused, 2 residual; 3 statements rendered */ return x;";
    assert_eq!(mismatches(hidden), ["2 residual, no site"]);
    let sited = "/* r2dec proof: 1 construct is marked below; 9 source obligations: 8 rendered, \
                 0 elided, 0 refused, 1 residual; 1 statements rendered */ \
                 return r2sleigh_residual_u64(1);";
    assert!(mismatches(sited).is_empty());
}
