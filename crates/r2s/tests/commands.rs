//! What the shell answers, run as the shell.
//!
//! These drive the binary this build produced, through `CARGO_BIN_EXE_r2s`, so
//! a test can never measure an older artifact than the code it is checking --
//! which is the mistake that once had a harness reporting a tree several
//! changes old because it defaulted to a binary the build command never wrote.
//!
//! The fixture is one of the programs the repository ships as bytes, so the
//! same assertion means the same program on every machine.

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

/// A GCC-built x86-64 ELF carried in the tree, not stripped.
fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/coverage/pinned/hashes_gcc_x64_O2")
}

/// One function of that fixture, by address: a small hash loop.
const FNV1A32: &str = "0x401330";

struct Run {
    out: String,
    ok: bool,
}

fn r2s(script: &str) -> Run {
    on(fixture(), script)
}

fn on(binary: PathBuf, script: &str) -> Run {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(binary)
        .output()
        .expect("the shell runs");
    Run {
        out: String::from_utf8_lossy(&done.stdout).into_owned()
            + &String::from_utf8_lossy(&done.stderr),
        ok: done.status.success(),
    }
}

#[test]
fn symbols_are_listed_with_their_kind() {
    let run = r2s("is");
    assert!(run.ok, "{}", run.out);
    assert!(run.out.contains("FUNC fnv1a32"), "{}", run.out);
    assert!(
        run.out.contains(FNV1A32.trim_start_matches("0x")),
        "{}",
        run.out
    );
}

#[test]
fn a_grep_suffix_keeps_only_matching_lines() {
    let run = r2s("is~fnv");
    assert!(run.ok, "{}", run.out);
    for line in run.out.lines().filter(|line| !line.trim().is_empty()) {
        assert!(line.contains("fnv"), "{line}");
    }
    assert!(run.out.contains("fnv1a64"), "{}", run.out);
}

#[test]
fn every_discovered_address_says_why_it_is_believed() {
    let run = r2s("afl");
    assert!(run.ok, "{}", run.out);
    let reasons = ["stated", "called", "reached"];
    let rows: Vec<&str> = run
        .out
        .lines()
        .filter(|line| line.trim_start().starts_with("0x"))
        .collect();
    assert!(!rows.is_empty(), "{}", run.out);
    for row in &rows {
        assert!(
            reasons.iter().any(|reason| row.contains(reason)),
            "no confidence on {row}"
        );
    }
    // Discovery may not lose a function the format states outright.
    assert!(
        rows.len() >= r2s("is").out.matches("FUNC").count(),
        "{}",
        run.out
    );
}

#[test]
fn a_temporary_seek_does_not_move_the_cursor() {
    let run = r2s(&format!("pd 1 @ {FNV1A32}; pd 1"));
    assert!(run.ok, "{}", run.out);
    let lines: Vec<&str> = run.out.lines().filter(|l| l.contains("0x")).collect();
    assert_eq!(lines.len(), 2, "{}", run.out);
    assert!(lines[0].contains("401330"), "{}", run.out);
    assert!(!lines[1].contains("401330"), "{}", run.out);
}

#[test]
fn a_named_address_is_spelled_by_its_name() {
    let run = r2s(&format!("s {FNV1A32}; pd 2"));
    assert!(run.ok, "{}", run.out);
    assert!(run.out.contains("endbr64"), "{}", run.out);
}

#[test]
fn a_function_renders_as_c_with_its_proof() {
    let run = r2s(&format!("s {FNV1A32}; pdd"));
    assert!(run.ok, "{}", run.out);
    assert!(run.out.contains("fnv1a32("), "{}", run.out);
    assert!(run.out.contains("r2dec proof:"), "{}", run.out);
    // This one is fully proven, and a regression here is a real loss.
    assert!(run.out.contains("0 refused"), "{}", run.out);
}

#[test]
fn each_tier_answers_for_itself() {
    // One lowering per tier, so a defect belongs to exactly one of them.
    let low = r2s(&format!("s {FNV1A32}; pdil"));
    let medium = r2s(&format!("s {FNV1A32}; pdim"));
    let high = r2s(&format!("s {FNV1A32}; pdih"));
    for run in [&low, &medium, &high] {
        assert!(run.ok, "{}", run.out);
        assert!(!run.out.trim().is_empty());
    }
    assert!(low.out.contains("Entry: 0x401330"), "{}", low.out);
    assert!(medium.out.contains("Function: fnv1a32"), "{}", medium.out);
    assert!(high.out.contains("Function: fnv1a32"), "{}", high.out);
    assert_ne!(low.out, medium.out);
    assert_ne!(medium.out, high.out);
}

#[test]
fn an_unmapped_address_is_refused_rather_than_invented() {
    let run = r2s("s 0x999999; pdd");
    assert!(!run.ok, "{}", run.out);
    assert!(run.out.contains("nothing mapped"), "{}", run.out);
}

#[test]
fn every_named_address_is_spelled_in_one_vocabulary() {
    let run = r2s("f");
    assert!(run.ok, "{}", run.out);
    // One table, one spelling per kind: what the container declared, what the
    // loader runs, what the linker stubs, what the data holds.
    for expected in [
        "sym.fnv1a32",
        "entry0",
        "entry.init0",
        "entry.fini0",
        "sym.imp.__printf_chk",
        "section..text",
    ] {
        assert!(
            run.out.contains(expected),
            "{expected} missing:\n{}",
            run.out
        );
    }
    // A function symbol is not also an entry: the symbol table already named
    // it, and two names for one address is the defect this table replaced.
    assert!(!run.out.contains("entry1"), "{}", run.out);
}

#[test]
fn a_string_is_named_only_where_it_is_terminated() {
    let run = r2s("f~str.");
    assert!(run.ok, "{}", run.out);
    let rows: Vec<&str> = run.out.lines().filter(|l| l.contains("str.")).collect();
    assert!(!rows.is_empty(), "{}", run.out);
    for row in &rows {
        // Size counts the terminator, so a named string is at least two bytes
        // and never zero-width.
        let size: u64 = row.split_whitespace().nth(1).unwrap().parse().unwrap();
        assert!(size >= 2, "{row}");
    }
}

#[test]
fn the_engine_and_the_listing_read_one_entry() {
    // `pdd` spells a call by the import's own name and `pd` writes the flag,
    // and both come from the same row rather than from two tables that can
    // drift apart.
    let listed = r2s("f~sym.imp.__printf_chk");
    assert!(listed.ok && !listed.out.trim().is_empty(), "{}", listed.out);
    let rendered = r2s("s 0x401050; pdd");
    assert!(rendered.ok, "{}", rendered.out);
    assert!(rendered.out.contains("__printf_chk"), "{}", rendered.out);
    assert!(!rendered.out.contains("sym_imp"), "{}", rendered.out);
}

#[test]
fn a_string_is_listed_as_itself_and_flagged_as_an_identifier() {
    // One row answers both: the text a reader wants and the name a listing
    // can write. They cannot drift because they are the same entry.
    let listed = r2s("iz");
    assert!(listed.ok, "{}", listed.out);
    assert!(
        listed.out.contains("/lib64/ld-linux-x86-64.so.2"),
        "{}",
        listed.out
    );
    let flagged = r2s("f~str._lib64");
    assert!(flagged.ok, "{}", flagged.out);
    assert!(
        flagged.out.contains("str._lib64_ld_linux_x86_64_so_2"),
        "{}",
        flagged.out
    );
}

#[test]
fn a_reference_is_a_query_over_the_lift() {
    let all = r2s("ax");
    assert!(all.ok, "{}", all.out);
    let rows: Vec<&str> = all
        .out
        .lines()
        .filter(|line| line.trim_start().starts_with("0x"))
        .collect();
    assert!(!rows.is_empty(), "{}", all.out);
    // Every reference says whether the address is named as code or as data.
    for row in &rows {
        let kind = row.split_whitespace().nth(2).unwrap_or("");
        assert!(kind == "c" || kind == "d", "{row}");
    }
    // And asking about one address gives back only the rows that name it.
    let first: Vec<&str> = rows[0].split_whitespace().collect();
    let one = r2s(&format!("axt {}", first[1]));
    assert!(one.ok, "{}", one.out);
    assert!(
        one.out.contains(first[0]),
        "{}\nlooking for {}",
        one.out,
        first[0]
    );
}

#[test]
fn a_patch_is_a_layer_the_analysis_reads_through() {
    // The file is untouched and every read sees the new bytes, so the
    // analysis of a patched program is the analysis of the program as
    // patched rather than of the one on disk.
    let before = r2s("s 0x401330; pd 1");
    assert!(before.out.contains("endbr64"), "{}", before.out);

    let patched = r2s("s 0x40133d; wx efbeadde; s 0x401330; pdd");
    assert!(patched.ok, "{}", patched.out);
    assert!(patched.out.contains("0xdeadbeef"), "{}", patched.out);

    // And the next session reads the file, because nothing was written to it.
    let again = r2s("s 0x401330; pdd");
    assert!(!again.out.contains("0xdeadbeef"), "{}", again.out);
}

#[test]
fn a_patch_is_listed_and_can_be_taken_back() {
    let run = r2s("s 0x401330; wx 9090; wc");
    assert!(run.ok, "{}", run.out);
    assert!(run.out.contains("2 patched bytes"), "{}", run.out);

    let reverted = r2s("s 0x401330; wx 9090; wcr; pd 1");
    assert!(reverted.ok, "{}", reverted.out);
    assert!(reverted.out.contains("endbr64"), "{}", reverted.out);
}

#[test]
fn a_write_where_nothing_is_mapped_is_refused() {
    let run = r2s("s 0x99990000; wx 90");
    assert!(!run.ok, "{}", run.out);
}

#[test]
fn the_image_reports_what_the_container_states() {
    let run = r2s("i");
    assert!(run.ok, "{}", run.out);
    assert!(run.out.contains("Elf"), "{}", run.out);
    assert!(run.out.contains("x86"), "{}", run.out);
}

/// The three tiers, pinned.
///
/// A lowering change should move exactly one of these. When one moves, read
/// the new output and judge it before blessing it: a snapshot that differs is
/// not a snapshot that is wrong, and a snapshot that agrees is evidence that
/// nothing moved rather than evidence that the output is right.
mod tiers {
    use super::{FNV1A32, r2s};

    #[test]
    fn low_tier_is_pinned() {
        let run = r2s(&format!("s {FNV1A32}; pdil"));
        assert!(run.ok, "{}", run.out);
        insta::assert_snapshot!("fnv1a32_r2il", run.out);
    }

    #[test]
    fn medium_tier_is_pinned() {
        let run = r2s(&format!("s {FNV1A32}; pdim"));
        assert!(run.ok, "{}", run.out);
        insta::assert_snapshot!("fnv1a32_r2ssa", run.out);
    }

    #[test]
    fn high_tier_is_pinned() {
        let run = r2s(&format!("s {FNV1A32}; pdih"));
        assert!(run.ok, "{}", run.out);
        insta::assert_snapshot!("fnv1a32_tree", run.out);
    }

    #[test]
    fn rendered_c_is_pinned() {
        let run = r2s(&format!("s {FNV1A32}; pdd"));
        assert!(run.ok, "{}", run.out);
        insta::assert_snapshot!("fnv1a32_c", run.out);
    }
}

/// An aarch64 Mach-O whose dispatcher calls through a table of function
/// pointers, which is the shape the engine has to derive for itself.
mod dispatch_table {
    use super::{Run, on};
    use std::path::PathBuf;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/code_pointer_table_O0")
    }

    fn r2s(script: &str) -> Run {
        on(fixture(), script)
    }

    #[test]
    fn a_call_through_a_table_renders_as_a_call_through_a_pointer() {
        let run = r2s("s 0x100000420; pdd");
        assert!(run.ok, "{}", run.out);
        // The dispatcher loads an entry and calls it. Spelling that as a
        // function-pointer call is the proof the target came from the table
        // rather than from a guess.
        assert!(run.out.contains("_table_dispatch("), "{}", run.out);
        assert!(run.out.contains(")(X0_0,"), "{}", run.out);
        assert!(run.out.contains("0 refused"), "{}", run.out);
    }

    #[test]
    fn the_table_entries_are_functions_in_their_own_right() {
        let run = r2s("afl");
        assert!(run.ok, "{}", run.out);
        for entry in ["_table_op_add", "_table_op_xor", "_table_op_mul"] {
            assert!(run.out.contains(entry), "{entry} missing from {}", run.out);
        }
    }
}

/// The same program with its symbol table removed.
///
/// Nothing states where a function is, so discovery has to read the program:
/// `entry0` hands `main` to `__libc_start_main`, whose declaration says that
/// parameter is a function, and everything below `main` follows from there.
mod stripped {
    use super::{Run, on};
    use std::path::PathBuf;

    fn fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/hashes_gcc_x64_O2_stripped")
    }

    fn r2s(script: &str) -> Run {
        on(fixture(), script)
    }

    #[test]
    fn the_symbol_table_states_nothing() {
        let run = r2s("is");
        assert!(run.ok, "{}", run.out);
        assert!(!run.out.contains("FUNC"), "{}", run.out);
    }

    #[test]
    fn main_is_found_because_a_declaration_says_that_parameter_is_a_function() {
        let run = r2s("afl");
        assert!(run.ok, "{}", run.out);
        // `main` is at 0x401050 in this build, and nothing calls it directly.
        let handed: Vec<&str> = run
            .out
            .lines()
            .filter(|line| line.contains("handed"))
            .collect();
        assert_eq!(handed.len(), 1, "{}", run.out);
        assert!(handed[0].contains("0x00401050"), "{}", run.out);
    }

    #[test]
    fn what_main_calls_is_found_with_it() {
        // Without the handoff the walk sees the entry, the stubs and what they
        // reach, and nothing else. Crossing it is worth the whole program.
        let run = r2s("afl");
        assert!(run.ok, "{}", run.out);
        let found = run
            .out
            .lines()
            .filter(|line| line.trim_start().starts_with("0x"))
            .count();
        assert!(found >= 20, "only {found} found:\n{}", run.out);
    }

    #[test]
    fn a_halt_does_not_leave_its_block_without_a_terminator() {
        // `hlt` lifts to a branch to its own address. Reading that as one step
        // of a repeating instruction left the block with no terminator, so the
        // machine graph named no successor while the walk named the self-edge,
        // and every function ending in `hlt` refused on the contradiction.
        let run = r2s("s 0x401240; pdd");
        assert!(run.ok, "{}", run.out);
        assert!(run.out.contains("0 refused"), "{}", run.out);
    }
}
