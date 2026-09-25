//! The review fixture, where the shell once ran out of memory or read data as code.
//!
//! `tests/fixtures/rv_O0g` is `tests/gold/review.c` built by GCC 13.3.0 at
//! `-O0 -g`. Its `classify` reloads the switch index from a stack slot the
//! guard never narrows, so the jump table read reaches every 32-bit index: a
//! sound fact about the program, and 16 GiB of table the program does not
//! have. The shell ran it through a 2^32-entry label vector and aborted.

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rv_O0g")
}

struct Run {
    out: String,
    ok: bool,
}

/// Run a script under a one-gigabyte address space and a ten-second clock,
/// so a regression fails this test rather than the machine running it.
fn bounded(script: &str) -> Run {
    let mut child = Command::new("sh")
        .args([
            "-c",
            r#"ulimit -v 1000000; exec "$0" -q -c "$1" "$2""#,
            env!("CARGO_BIN_EXE_r2s"),
            script,
        ])
        .arg(fixture())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the shell runs");
    let started = Instant::now();
    while child.try_wait().expect("the shell is waited on").is_none() {
        if started.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            panic!("`{script}` ran past ten seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let done = child.wait_with_output().expect("the shell's output");
    Run {
        out: String::from_utf8_lossy(&done.stdout).into_owned()
            + &String::from_utf8_lossy(&done.stderr),
        ok: done.status.success(),
    }
}

#[test]
fn a_switch_read_through_an_unbounded_index_is_listed_within_a_gigabyte() {
    let run = bounded("pdf @ sym.classify");
    assert!(run.ok, "{}", run.out);
    assert!(!run.out.contains("memory allocation"), "{}", run.out);
    // The guard, the dispatch and the default are the function's bytes, and
    // the dispatch the analysis cannot bound says so rather than guessing.
    for line in ["0x00001219", "0x0000123c", "0x00001276"] {
        assert!(run.out.contains(line), "{line} missing:\n{}", run.out);
    }
}

#[test]
fn a_switch_whose_table_the_program_does_not_have_is_no_tail_call() {
    // With the table refused, the dispatch is where the walk stopped. It was
    // rendered as `return ((int32_t(*)(void))*(...))();` under "0 refused".
    for script in [
        "pdd @ sym.classify",
        "afi @ sym.classify",
        "afv @ sym.classify",
    ] {
        let run = bounded(script);
        assert!(run.ok, "{script}: {}", run.out);
        assert!(!run.out.contains(")()"), "{script}: {}", run.out);
    }
}

#[test]
fn an_address_in_read_only_data_is_no_function() {
    // 0x2020 is the third entry of classify's jump table, in the segment
    // mapped read-only. Its bytes happen to decode, so the shell listed
    // `xor eax, 0x3cfffff2` there and rendered `void fcn_2020(void)` under a
    // clean proof line: data, presented as a function.
    for script in ["s 0x2020; pdd", "s 0x2020; pdf"] {
        let run = bounded(script);
        assert!(!run.ok, "{script}: {}", run.out);
        assert!(
            run.out.contains(
                "no instruction can run at 0x2020: the program maps it without execute permission"
            ),
            "{script}: {}",
            run.out
        );
        assert!(!run.out.contains("fcn_2020"), "{script}: {}", run.out);
        assert!(!run.out.contains("xor eax"), "{script}: {}", run.out);
    }
}
