//! An answer is a function of the bytes and the request, never of the commands before it (D573).

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

const HASHES: &str = "tests/coverage/pinned/hashes_gcc_x64_O2";
/// `fnv1a32`, whose result only a call in `main` reads.
const FNV1A32: u64 = 0x401330;
/// `djb2` and `murmur3_32`, asked before it in either order.
const OTHERS: [u64; 2] = [0x4013b0, 0x401680];

fn shell(fixture: &str, script: &str) -> String {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(fixture);
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(binary)
        .output()
        .expect("the shell runs");
    assert!(done.status.success(), "{script}: {done:?}");
    String::from_utf8_lossy(&done.stdout).into_owned()
}

/// `pdd`, `pdf` and `afi` print the same bytes alone, after `aa`, after `afl`, and after two other
/// functions' `pdd` in both orders.
#[test]
fn an_answer_is_the_same_whatever_ran_before_it() {
    let [one, two] = OTHERS;
    for command in ["pdd", "pdf", "afi"] {
        let asked = format!("{command} @ {FNV1A32:#x}");
        let alone = shell(HASHES, &asked);
        assert!(!alone.is_empty(), "{asked}");
        let prefixes = [
            "aa".to_owned(),
            "afl".to_owned(),
            format!("pdd @ {one:#x}; pdd @ {two:#x}"),
            format!("pdd @ {two:#x}; pdd @ {one:#x}"),
        ];
        for prefix in prefixes {
            let before = shell(HASHES, &prefix);
            let after = shell(HASHES, &format!("{prefix}; {asked}"));
            assert_eq!(after, format!("{before}{alone}"), "`{prefix}; {asked}`");
        }
    }
}

/// Every request reads the program's callers: `aa` is a survey and moves no answer.
#[test]
fn a_cold_answer_names_the_closed_world_it_reads() {
    let text = shell(HASHES, &format!("pdd @ {FNV1A32:#x}"));
    assert!(text.contains("assuming closed-world"), "{text}");
}

/// `_init` writes RAX on its path to `ret` and nothing reads it: the `ret` note states the result
/// `afi` states, never `returns rax` (D584; bomb `phase_3` is the same class).
#[test]
fn a_ret_note_states_the_result_afi_states() {
    let listing = shell(HASHES, "pdf @ 0x401000");
    let info = shell(HASHES, "afi @ 0x401000");
    assert!(info.contains("result: unproven ; ! rax, Written"), "{info}");
    // An unproven result is a refusal kind: `!`, no basis word (D579's speller at the merge).
    assert!(
        listing.contains("ret ; ! result unproven (rax, Written)"),
        "{listing}"
    );
    assert!(!listing.contains("returns rax"), "{listing}");
}
