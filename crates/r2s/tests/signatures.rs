//! `afi` states the signature the decompiler declares, from the same analysis.

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

/// A GCC-built x86-64 ELF carried in the tree, not stripped.
fn pinned(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/coverage/pinned")
        .join(name)
}

fn r2s(script: &str) -> String {
    r2s_on("hashes_gcc_x64_O2", script)
}

fn r2s_on(fixture: &str, script: &str) -> String {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(pinned(fixture))
        .output()
        .expect("the shell runs");
    assert!(
        done.status.success(),
        "{}",
        String::from_utf8_lossy(&done.stderr)
    );
    String::from_utf8_lossy(&done.stdout).into_owned()
}

/// The return type and each parameter's type, as a C header spells them.
fn header_types(header: &str) -> (String, Vec<String>) {
    let (head, parameters) = header
        .trim_end_matches(')')
        .split_once('(')
        .expect("a parameter list");
    let (returns, _name) = head.trim_end().rsplit_once(' ').expect("a return type");
    let parameters = parameters
        .split(", ")
        .filter(|parameter| !parameter.is_empty())
        .map(|parameter| {
            let (ty, _name) = parameter.rsplit_once(' ').expect("a typed parameter");
            ty.to_owned()
        })
        .collect();
    (returns.to_owned(), parameters)
}

#[test]
fn afi_states_the_signature_pdd_declares() {
    let info = r2s("afi @ 0x401330");
    let signature = info
        .lines()
        .find_map(|line| line.strip_prefix("signature: "))
        .unwrap_or_else(|| panic!("afi states no signature:\n{info}"));
    assert_eq!(
        signature,
        "uint64_t sym.fnv1a32 (uint64_t arg1, uint64_t arg2);"
    );
    let rendered = r2s("pdd @ 0x401330");
    let header = rendered.lines().next().expect("a header");
    assert_eq!(
        header_types(signature.trim_end_matches(';')),
        header_types(header),
        "afi and pdd disagree about what fnv1a32 takes and returns"
    );
}

#[test]
fn pdd_declares_every_formal_the_interface_has_even_unread() {
    // `vfold` spills six carriers for `va_start` and `main` never reads `argv`; the interface keeps both.
    for (function, arity) in [("sym.vfold", 6), ("main", 3)] {
        let info = r2s_on("shapes_gcc_x64_O0", &format!("afi @ {function}"));
        let signature = info
            .lines()
            .find_map(|line| line.strip_prefix("signature: "))
            .unwrap_or_else(|| panic!("afi states no signature:\n{info}"));
        let rendered = r2s_on("shapes_gcc_x64_O0", &format!("pdd @ {function}"));
        let header = rendered.lines().next().expect("a header");
        let (_, afi) = header_types(signature.trim_end_matches(';'));
        let (_, pdd) = header_types(header);
        assert_eq!(pdd.len(), arity, "{header}");
        assert_eq!(afi, pdd, "{signature}\n{header}");
    }
}

#[test]
fn afi_says_noreturn_only_where_the_program_proves_it() {
    let stub = r2s_on("branchy_gcc_x64_O0", "afi @ sym.imp.__stack_chk_fail");
    assert!(stub.lines().any(|line| line == "noreturn: true"), "{stub}");
    let body = r2s("afi @ 0x401330");
    assert!(
        !body.lines().any(|line| line.starts_with("noreturn")),
        "{body}"
    );
}
