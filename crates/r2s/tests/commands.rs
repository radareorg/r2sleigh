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

/// One function of that fixture whose tail shifts by an immediate.
const MURMUR3_32: &str = "0x401680";

#[test]
fn a_shift_by_an_immediate_does_not_read_the_flags_it_sets() {
    // `shr rax, 2` keeps its flags when the count is zero, and Sleigh lifts that
    // guard; with the count decided the guard is dead and must not read ZF.
    let run = r2s(&format!("s {MURMUR3_32}; pdd"));
    assert!(run.ok, "{}", run.out);
    assert!(run.out.contains("murmur3_32("), "{}", run.out);
    assert!(!run.out.contains("r2sleigh refused"), "{}", run.out);
    assert!(run.out.contains("if (RAX_2 != 0)"), "{}", run.out);
    for flag in ["ZF", "CF_0", "OF_0", "PF_0", "SF_0"] {
        assert!(!run.out.contains(flag), "{flag} is read by {}", run.out);
    }
}

#[test]
fn the_ledger_says_what_the_function_owes_and_whether_it_paid() {
    // The counts behind `pdd`'s proof line, which used to reach only a file
    // behind an environment variable.
    let run = r2s(&format!("s {FNV1A32}; pddo"));
    assert!(run.ok, "{}", run.out);
    for column in ["total=", "rendered=", "elided=", "refused=", "unaccounted="] {
        assert!(
            run.out.contains(column),
            "{column} missing from {}",
            run.out
        );
    }
    assert!(run.out.contains("refused=0"), "{}", run.out);
    // A breakdown, not just columns: this function elides something and says why.
    assert!(run.out.contains("| elided: "), "{}", run.out);
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

/// A seek reads the same table `f` lists, so a flag name goes where `f` says.
#[test]
fn a_flag_name_seeks_where_the_flag_table_puts_it() {
    let flagged = r2s("f~entry0");
    assert!(flagged.ok, "{}", flagged.out);
    let listed = flagged
        .out
        .split_whitespace()
        .next()
        .and_then(|addr| u64::from_str_radix(addr.trim_start_matches("0x"), 16).ok())
        .expect("f lists entry0");
    let spelled = format!("{listed:#x}");
    // The session starts there, and `s entry0` agrees with both.
    let run = r2s("s; s entry0; s; s sym.fnv1a32; s; s fnv1a32; s; s 4199216; s");
    assert!(run.ok, "{}", run.out);
    let seeks: Vec<&str> = run.out.lines().collect();
    assert_eq!(
        seeks,
        [
            spelled.as_str(),
            spelled.as_str(),
            FNV1A32,
            FNV1A32,
            FNV1A32
        ],
        "{}",
        run.out
    );
}

#[test]
fn an_unknown_name_is_refused_and_the_cursor_stays() {
    let run = r2s(&format!("s {FNV1A32}; s sym.no_such_function; s"));
    assert!(!run.ok, "{}", run.out);
    assert!(
        run.out
            .contains("unknown address or flag 'sym.no_such_function'"),
        "{}",
        run.out
    );
    assert!(run.out.contains(FNV1A32), "{}", run.out);
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

/// A patch moves what the image says about itself, not only what it reads as.
///
/// The import table is *decoded*: which address is a linkage stub, and which
/// import it stands for, comes from lifting the stub and following the slot it
/// reads. So does the set of addresses a body walk may not run past, because
/// `is_entry` answers from that same table. Deriving it once and holding it
/// meant a patched stub left the walk bounded by a function that was no longer
/// there -- a wrong body, reported as a clean one.
#[test]
fn patching_a_stub_derives_the_import_table_again() {
    let stub = "0x401040";

    // The table has to be derived *before* the patch for staleness to be
    // possible at all: one `f` decodes the stubs, the patch removes one, and
    // the second `f` is the question. Each of these is one process, so a
    // sequence that patches before it ever asks would pass either way.
    let run = r2s(&format!("s {stub}; f~imp; wx 9090909090909090; f~imp"));
    assert!(run.ok, "{}", run.out);
    let (before, after) = run
        .out
        .split_once("8 bytes at")
        .expect("the write reports what it wrote");
    assert!(
        before.contains("sym.imp.__printf_chk"),
        "the fixture should name the stub before the patch: {}",
        run.out
    );
    assert!(
        !after.contains("sym.imp.__printf_chk"),
        "the import survived a patch that removed the stub it was decoded from: {}",
        run.out
    );

    // And taking the patch back takes the import back, in the same session.
    let restored = r2s(&format!("s {stub}; f~imp; wx 9090909090909090; wcr; f~imp"));
    assert!(restored.ok, "{}", restored.out);
    let (_, after) = restored
        .out
        .split_once("8 bytes at")
        .expect("the write reports what it wrote");
    assert!(
        after.contains("sym.imp.__printf_chk"),
        "reverting the patch did not restore the import: {}",
        restored.out
    );
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

/// The listing, pinned on one binary per architecture the tree carries.
///
/// `pd` is the command with the least protection and the most rewriting: every
/// line it prints is built by successive substitutions over one formatted
/// string, and until now a change to any of them was caught only by a
/// comparison against radare2 that lives outside this repository. These pin the
/// spellings that rewriting is meant to preserve, so a listing that changes is
/// a listing someone decided to change.
///
/// What each one covers, beyond the decode:
///
/// - x86-64: the `ptr` and displacement spellings, and `jz` printed as `jne`'s
///   comparison rather than its flag.
/// - aarch64: a Mach-O whose operands reach data through a page and an offset.
/// - ARM 32-bit: the register roles (`fp`, `ip`, `sp`, `lr`, `pc`), the `mov`
///   alias for the encoding Sleigh spells `cpy`, and a big-endian Thumb-2
///   decode, which is the one place this engine reads an instruction radare2
///   reads wrongly.
///
/// Two spellings in these recordings are ours and not radare2's, and they are
/// pinned so that changing them is a decision rather than an accident. The x86
/// snapshot writes `nop word ptr cs:[rax + rax*0x1]`, because the rule that
/// drops `ptr` matches ` ptr [` and this operand carries a segment between the
/// two; and it writes a sixty-four-bit immediate signed, as Sleigh does, where
/// radare2 writes it unsigned. The listing comparison against radare2
/// normalises integers, so neither shows up there.
mod listing {
    use super::{FNV1A32, Run, on, r2s};
    use std::path::PathBuf;

    fn at(fixture: &str, script: &str) -> Run {
        on(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(fixture),
            script,
        )
    }

    #[test]
    fn the_x86_listing_is_pinned() {
        let run = r2s(&format!("s {FNV1A32}; pd 24"));
        assert!(run.ok, "{}", run.out);
        insta::assert_snapshot!("fnv1a32_pd", run.out);
    }

    /// The annotations, on the one pinned binary that has all three shapes:
    /// a call through a relocated slot, a jump through an unnamed one, and a
    /// compare against a data byte.
    #[test]
    fn what_a_line_reads_is_pinned() {
        let run = super::r2s("s 0x401000; pd 24");
        assert!(run.ok, "{}", run.out);
        insta::assert_snapshot!("reads_pd", run.out);
    }

    /// The listing radare2 cannot write: no range that is one value the instruction fixes or only the width it wrote, each note ending in its rung.
    #[test]
    fn what_the_engine_proved_is_pinned() {
        let run = super::r2s("s 0x401330; pdf; s 0x401530; pdf");
        assert!(run.ok, "{}", run.out);
        // A move of a constant fixes its one value, so a range would only restate the operand.
        for restated in ["defines rax = 0x811c9dc5", "defines rdx = 0x8"] {
            assert!(!run.out.contains(restated), "{restated}: {}", run.out);
        }
        // The mask bounds the value by evaluating the and alone, so the instruction's own bound is decoded.
        assert!(
            run.out
                .contains("and eax, 0x1 ; defines rax in [0x0, 0x1] (decoded)"),
            "{}",
            run.out
        );
        // The loop's header carries the byte pointer, one further each trip, and runs once per byte of the length.
        let header = run.out.lines().find(|line| line.contains("0x00401348"));
        let header = header.unwrap_or_default();
        for said in [
            "induction rdi = rdi@entry, +0x1 per trip (certified)",
            "trips rsi@entry (solved)",
        ] {
            assert!(header.contains(said), "{said}: {}", run.out);
        }
        insta::assert_snapshot!("proved_pdf", run.out);
    }

    /// Each arm of siphash24's tail switch is labelled with the cases the dispatch sends there, as radare2 labels them.
    #[test]
    fn every_case_the_decompiler_renders_is_a_label_in_the_listing() {
        let listed = super::r2s("s sym.siphash24; pdf");
        assert!(listed.ok, "{}", listed.out);
        let rendered = super::r2s("s sym.siphash24; pdd");
        let cases = rendered.out.lines().filter_map(|line| {
            let case = line.trim().strip_prefix("case ")?.strip_suffix(':')?;
            case.parse::<u64>().ok()
        });
        let cases = cases.collect::<Vec<_>>();
        assert_eq!(cases.len(), 8, "{}", rendered.out);
        for case in cases {
            let label = format!(";-- case {case}:");
            let label = listed
                .out
                .lines()
                .find(|line| line.trim_start().starts_with(&label));
            assert!(
                label.is_some_and(|line| line.ends_with("; from 0x0040197e")),
                "case {case}: {}",
                listed.out
            );
        }
        let dispatch = "; switch table (8 cases) at 0x402020 (solved)";
        assert!(listed.out.contains(dispatch), "{}", listed.out);
        insta::assert_snapshot!("siphash_pdf", listed.out);
    }

    /// A line that hands a string to a call says the text beside the address, on the rung the address stands on.
    #[test]
    fn a_line_says_the_text_at_an_address_it_hands_on() {
        let run = super::r2s("s main; pd 8");
        assert!(run.ok, "{}", run.out);
        let format = run
            .out
            .lines()
            .find(|line| line.contains("0x0040106c"))
            .unwrap_or_default();
        // `__printf_chk` is declared to take its format as a pointer, and the number stays put.
        assert!(
            format.ends_with(r#"mov esi, str.fnv1a32______08x_ ; "fnv1a32     %08x\n" (declared)"#),
            "{}",
            run.out
        );
    }

    /// A function is its blocks. The alignment padding after the loop's `ret`
    /// belongs to no block, and a linear sweep from the lowest block to the
    /// highest listed it -- or, for a cold partition placed far away, the
    /// whole gap between.
    #[test]
    fn a_function_listing_is_its_blocks_and_nothing_between() {
        let run = super::r2s("s 0x401330; pdf");
        assert!(run.ok, "{}", run.out);
        assert!(run.out.contains("0x0040135c"), "{}", run.out);
        assert!(!run.out.contains("0x0040135d"), "{}", run.out);
        assert!(run.out.contains("0x00401360"), "{}", run.out);
    }

    #[test]
    fn a_function_listing_of_nothing_says_so() {
        let run = super::r2s("s 0x10; pdf");
        assert!(!run.ok);
        assert!(run.out.contains("nothing mapped at 0x10"), "{}", run.out);
    }

    /// `pd` stays cheap: the expensive listing is the one that was asked for.
    #[test]
    fn a_plain_listing_proves_nothing_about_a_value() {
        let plain = super::r2s("s 0x401530; pd 16");
        let proved = super::r2s("s 0x401530; pdf");
        assert!(!plain.out.contains("defines "), "{}", plain.out);
        assert!(proved.out.contains(" in ["), "{}", proved.out);
    }

    #[test]
    fn the_aarch64_listing_is_pinned() {
        let run = at(
            "tests/fixtures/code_pointer_table_O0",
            "s 0x100000420; pd 24",
        );
        assert!(run.ok, "{}", run.out);
        insta::assert_snapshot!("table_dispatch_pd", run.out);
    }

    /// `pdf` folds each block of the walked body across its lines, so the page and its offset are one address and the table load reads it; `pd` folds each line alone.
    #[test]
    fn the_aarch64_function_listing_folds_each_block() {
        let fixture = "tests/fixtures/code_pointer_table_O0";
        let run = at(fixture, "pdf @ sym._table_dispatch");
        assert!(run.ok, "{}", run.out);
        let page = "add x8, x8, 0x0 ; defines x8 = 0x100004000 (folded)";
        assert!(run.out.contains(page), "{}", run.out);
        // The word is a chained fixup dyld rebases to 0x100000400, so what the file holds there is no value to state.
        let load = run
            .out
            .lines()
            .find(|line| line.contains("ldr x8, [x8, 0x10]"));
        assert!(
            load.is_some_and(|line| line.ends_with("ldr x8, [x8, 0x10]")),
            "{}",
            run.out
        );
        let read = at(fixture, "axt 0x100004010");
        let named = "sym._table_dispatch 0x100000444 [DATA:r--] ldr x8, [x8, 0x10]\n";
        assert!(read.out.starts_with(named), "{}", read.out);
        let plain = at(fixture, "s 0x100000420; pd 24");
        assert!(!plain.out.contains("0x100004010"), "{}", plain.out);
        insta::assert_snapshot!("table_dispatch_pdf", run.out);
    }

    #[test]
    fn the_arm_listing_is_pinned() {
        let run = at("crates/r2image/tests/data/arm_thumb_entry.elf", "pd 12");
        assert!(run.ok, "{}", run.out);
        insta::assert_snapshot!("arm_thumb_pd", run.out);
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

    /// The block counts and the frame are the prepared analysis's: the saved
    /// `x29`/`x30` pair is frame management, the two spills of `x0`/`x1` and
    /// the promoted loop counter are the body's own.
    #[test]
    fn a_function_reports_its_shape_and_its_frame() {
        let run = r2s("afi @ sym._table_dispatch; afv @ sym._table_dispatch");
        assert!(run.ok, "{}", run.out);
        for line in [
            "name: sym._table_dispatch",
            "size: 152",
            "num-bbs: 6",
            "num-instrs: 38",
            "cyclomatic-complexity: 2",
            "is-lineal: true",
            "locals: 5",
            "args: 2",
        ] {
            assert!(
                run.out.lines().any(|out| out == line),
                "{line}: {}",
                run.out
            );
        }
        let frame = run.out.lines().skip_while(|line| !line.starts_with("arg "));
        let frame = frame.collect::<Vec<_>>().join("\n");
        assert_eq!(
            frame,
            "arg uint64_t arg1 @ x0\n\
             arg uint64_t arg2 @ x1\n\
             var uint32_t stack_m76 @ entry.sp-0x4c\n\
             var uint64_t stack_m72 @ entry.sp-0x48\n\
             var struct r2sleigh_bits_192 stack_m64 @ entry.sp-0x40\n\
             var uint64_t stack_m32 @ entry.sp-0x20\n\
             var uint64_t stack_m24 @ entry.sp-0x18"
        );
    }

    #[test]
    fn a_function_query_where_nothing_is_mapped_is_refused() {
        for command in ["afi @ 0x10", "afv @ 0x10"] {
            let run = r2s(command);
            assert!(!run.ok, "{command}: {}", run.out);
            assert!(run.out.contains("0x10"), "{command}: {}", run.out);
        }
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

#[test]
fn entry0_is_the_declared_entry_where_the_format_names_it_main() {
    // `LC_MAIN` puts `main` on the entry, and radare2 answers `entry0` there too.
    let macho = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../r2image/tests/data/function_starts.macho");
    let run = on(macho, "s entry0; s; s main; s");
    assert!(run.ok, "{}", run.out);
    assert_eq!(run.out.lines().collect::<Vec<_>>(), ["0x100000344"; 2]);
}
