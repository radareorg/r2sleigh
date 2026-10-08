//! A binary whose headers state more than it holds costs no more than the file (ROADMAP H, D18).

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Run one script over one fixture, killing it past `limit`; its exit code where it finished in time.
fn finishes_within(fixture: &str, script: &str, limit: Duration) -> Option<i32> {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(fixture);
    let mut child = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(binary)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the shell runs");
    let start = Instant::now();
    while start.elapsed() < limit {
        if let Some(status) = child.try_wait().expect("the shell is waited for") {
            // A signal leaves no code, and a panic exits 101: neither is a finish.
            return status.code();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    None
}

/// Finished in time, with success (0) or a refusal (1).
fn finishes_cleanly(fixture: &str, script: &str) -> bool {
    matches!(
        finishes_within(fixture, script, Duration::from_secs(30)),
        Some(0 | 1)
    )
}

/// `fuzzed/elf9`'s `.init_array` states a size past the file's end; opening it read a slot for
/// every word that size names, and never returned.
#[test]
fn an_init_array_larger_than_the_file_opens() {
    assert!(finishes_cleanly("fuzzed_elf9", "q"));
}

/// `fuzzed/file12`'s `__cstring` states 1 GiB past an 8.7 KB file; naming strings read and
/// copied all of it.
#[test]
fn a_string_section_larger_than_the_file_is_scanned_where_it_is_held() {
    assert!(finishes_cleanly("fuzzed_file12", "pd 5"));
}
