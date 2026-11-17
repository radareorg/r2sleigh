//! `pdie`: the lift of a recorded leaf run by `r2il::eval` from the recording's entry state
//! (ROADMAP D467); `scripts/run_refuter.py` sets the answer beside the machine's own run.

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `pdie RECORDING` on the hashes fixture: the exit status and what it printed.
fn pdie(recording: &std::path::Path) -> (bool, String) {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", &format!("pdie {}", recording.display())])
        .arg(root().join("tests/coverage/pinned/hashes_gcc_x64_O2"))
        .output()
        .expect("the shell runs");
    let out =
        String::from_utf8_lossy(&done.stdout).into_owned() + &String::from_utf8_lossy(&done.stderr);
    (done.status.success(), out)
}

/// FNV-1a of "abc" is 0x1a47e90b, and the lift returns it to the recorded return address.
#[test]
fn a_recorded_leaf_returns_its_value_to_the_recorded_return_address() {
    let (ok, out) = pdie(&root().join("tests/refuter/hashes_fnv1a32.json"));
    assert!(ok, "{out}");
    let answer: serde_json::Value = serde_json::from_str(&out).expect("one JSON object");
    assert_eq!(answer["results"]["RAX"], "0x1a47e90b", "{out}");
    assert_eq!(answer["stop"]["kind"], "returned", "{out}");
    assert_eq!(answer["stop"]["to"], "0xdeadbeef", "{out}");
}

/// A byte the recording does not hold stops the run where it is read, naming the address a
/// recorder adds next; a recording that is not there is an error.
#[test]
fn a_byte_the_recording_lacks_stops_the_run_and_names_it() {
    let recorded = std::fs::read_to_string(root().join("tests/refuter/hashes_fnv1a32.json"))
        .expect("the recording reads");
    let mut recording: serde_json::Value = serde_json::from_str(&recorded).expect("JSON");
    recording["cells"]
        .as_object_mut()
        .expect("cells")
        .remove("0x7fff0000");
    let path = std::env::temp_dir().join(format!("pdie-{}.json", std::process::id()));
    std::fs::write(&path, recording.to_string()).expect("written");
    let (ok, out) = pdie(&path);
    std::fs::remove_file(&path).expect("removed");
    assert!(ok, "{out}");
    let answer: serde_json::Value = serde_json::from_str(&out).expect("one JSON object");
    assert_eq!(answer["stop"]["kind"], "unrecorded", "{out}");
    assert_eq!(answer["stop"]["address"], "0x7fff0000", "{out}");
    let (ok, out) = pdie(&root().join("tests/refuter/absent.json"));
    assert!(!ok && out.contains("pdie:"), "{out}");
}
