//! `ax` and `axt`: each reference with how its instruction uses the address, laid out as radare2 lays `axt` out.

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

/// The shell's output on a binary carried in the tree, by its path from the workspace root.
fn on(binary: &str, script: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(binary);
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(path)
        .output()
        .expect("the shell runs");
    let out =
        String::from_utf8_lossy(&done.stdout).into_owned() + &String::from_utf8_lossy(&done.stderr);
    assert!(done.status.success(), "{out}");
    out
}

/// A GCC-built x86-64 ELF, not stripped.
fn hashes(script: &str) -> String {
    on("tests/coverage/pinned/hashes_gcc_x64_O2", script)
}

#[test]
fn axt_names_the_function_the_instruction_and_how_it_uses_the_address() {
    // As radare2 writes it: the function holding the instruction, where it is, the type and permissions, the instruction.
    let called = hashes("axt @ 0x401330");
    assert!(
        called.starts_with("sym.main 0x401067 [CALL:--x] call sym.fnv1a32\n"),
        "{called}"
    );
    // The import stub reads its slot; it does not execute there.
    let slot = hashes("axt 0x404000");
    assert!(
        slot.starts_with(
            "sym.imp.__printf_chk 0x401044 [DATA:r--] jmp qword [reloc.__printf_chk]\n"
        ),
        "{slot}"
    );
    // A string's address handed to a parameter declared a pointer is a value the instruction computes, not a read.
    let handed = hashes("axt 0x4021a0");
    assert!(
        handed.starts_with("sym.main 0x40106c [DATA:---] mov esi, str.fnv1a32______08x_\n"),
        "{handed}"
    );
}

#[test]
fn ax_lists_each_role_with_its_width_and_support() {
    let all = hashes("ax");
    let rows = all
        .lines()
        .filter(|line| line.starts_with("0x"))
        .collect::<Vec<_>>();
    assert!(
        rows.contains(&"0x00401067 0x00401330 CALL:--x    - decoded"),
        "{all}"
    );
    assert!(
        rows.contains(&"0x00401044 0x00404000 DATA:r--    8 decoded"),
        "{all}"
    );
    assert!(
        rows.contains(&"0x0040106c 0x004021a0 DATA:---    - declared"),
        "{all}"
    );
    // And every row `axt` answers for one address is one of these rows.
    let first = rows[0].split_whitespace().collect::<Vec<_>>();
    let one = hashes(&format!("axt {}", first[1]));
    let from = format!(
        " {:#x} [{}] ",
        u64::from_str_radix(&first[0][2..], 16).unwrap(),
        first[2]
    );
    assert!(one.contains(&from), "{one}\nlooking for {from}");
}

#[test]
fn no_reference_is_absence_within_what_was_read() {
    // Nothing names the second byte of the ELF magic, and saying so is a
    // claim about the functions read, not about the program.
    let none = hashes("axt 0x400001");
    assert!(none.contains("0 references to 0x400001"), "{none}");
    assert!(
        none.contains("\n; none within the functions read"),
        "{none}"
    );
    assert!(none.contains("\n; covers "), "{none}");
    // And the whole index says the same scope beneath its rows.
    let all = hashes("ax");
    let last = all.trim_end().lines().last().unwrap_or("");
    assert!(last.starts_with("; covers "), "{all}");
}
