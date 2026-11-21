//! D577: damaged ELF headers open as far as their header and program headers state, and a raw
//! blob opens at 0 (fixtures from `tests/fixtures/damaged_elf.py`).

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn run(args: &[&str], name: &str, script: &str) -> (bool, String, String) {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(args)
        .args(["-q", "-c", script])
        .arg(fixture(name))
        .output()
        .expect("the shell runs");
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    (
        done.status.success(),
        text(&done.stdout),
        text(&done.stderr),
    )
}

/// Each crackme whose section table `object` refuses opens and lists the same functions, entry0
/// among them; `iS` lists none. The stub at 0x400578 is `__libc_start_main`'s, whose handed `main`,
/// `__libc_csu_init` and `__libc_csu_fini` are listed (D636).
#[test]
fn a_refused_section_table_leaves_the_segments_and_the_dynamic_table() {
    let damaged = [
        "crackme_shoff_past_end",
        "crackme_shoff_high",
        "crackme_shoff_byte2",
        "crackme_shentsize",
        "crackme_shentsize_strndx",
    ];
    let mut listings = Vec::new();
    for name in damaged {
        let (ok, out, err) = run(&[], name, "i~refused; iS~.text; afl");
        assert!(ok, "{name}: {err}");
        let mut lines = out.lines();
        let refused = lines.next().expect("the refusal row");
        assert!(
            refused.starts_with("sections refused: Invalid ELF section header"),
            "{name}: {refused}"
        );
        let functions = lines.map(str::to_owned).collect::<Vec<_>>();
        for (start, what) in [
            ("0x004005c0 ", "entry0"),
            (
                "0x00400578    1      6 sym.imp.__libc_start_main",
                "the stub",
            ),
            ("0x004006a4 ", "main"),
            ("0x00400730 ", "__libc_csu_fini"),
            ("0x00400740 ", "__libc_csu_init"),
        ] {
            assert!(
                functions.iter().any(|row| row.starts_with(start)),
                "{name}: {what}: {functions:?}"
            );
        }
        listings.push(functions);
    }
    assert!(listings.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn an_unknown_machine_is_named_with_its_value() {
    let (ok, out, err) = run(&[], "crackme_unknown_machine", "i");
    assert!(!ok && out.is_empty());
    assert_eq!(
        err.trim_end(),
        "r2s: this build decodes no code for e_machine 0x653e"
    );
}

/// mutant 2: `e_entry` 0x40052f lies in `.rela.plt`; `ie` lists it, and nothing walks from it.
#[test]
fn an_entry_no_code_backs_is_listed_and_seeds_nothing() {
    let (ok, out, err) = run(&[], "crackme_entry_in_data", "ie; afl");
    assert!(ok, "{err}");
    assert!(
        out.contains("0x0040052f 0x00000018 0x00400018 program"),
        "{out}"
    );
    assert!(
        !out.lines().any(|row| row.starts_with("0x0040052f ")),
        "{out}"
    );
}

/// radare2 lists one function at 0 for a raw blob; no container states one, so `afl` is empty
/// (judged deliberate) while `pd` decodes on request.
#[test]
fn a_raw_blob_opens_at_zero_and_states_no_function() {
    let (ok, out, err) = run(
        &["-a", "x86", "-b", "64"],
        "raw_x64_start.bin",
        "afl; pd 1 @ 0",
    );
    assert!(ok, "{err}");
    assert_eq!(out.trim(), "0x00000000      31ed           xor ebp, ebp");
}
