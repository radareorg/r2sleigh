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

mod common;

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, PoisonError};

/// A GCC-built x86-64 ELF carried in the tree, not stripped.
fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/coverage/pinned/hashes_gcc_x64_O2")
}

/// Spawns take this in turn, and a test that closes a pipe to meet its writer holds it from the close
/// to the exit: `doc/testing.md`, "Closed pipes".
static SPAWNING: Mutex<()> = Mutex::new(());

/// Start `command` with its output piped and its input empty, as `output` would.
fn started(command: &mut Command) -> Child {
    let _spawning = SPAWNING.lock().unwrap_or_else(PoisonError::into_inner);
    (command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()))
    .spawn()
    .expect("the shell runs")
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
    let done = started(
        Command::new(env!("CARGO_BIN_EXE_r2s"))
            .args(["-q", "-c", script])
            .arg(binary),
    )
    .wait_with_output()
    .expect("the shell is waited for");
    Run {
        out: String::from_utf8_lossy(&done.stdout).into_owned()
            + &String::from_utf8_lossy(&done.stderr),
        ok: done.status.success(),
    }
}

/// An import stub is the import's declaration: its jump through the slot
/// the loader fills reaches the import exactly as a call to the stub does,
/// so it is declared by the same prototype. It used to refuse, saying
/// nothing stated one, because only direct calls were declared.
#[test]
fn an_import_stub_renders_as_the_import_it_jumps_to() {
    let run = r2s("pdd @ sym.imp.__printf_chk");
    assert!(run.ok, "{}", run.out);
    assert!(
        run.out
            .contains("extern int32_t __printf_chk(int32_t, const char*, ...);"),
        "{}",
        run.out
    );
    assert!(!run.out.contains("refused"), "{}", run.out);
}

#[test]
fn symbols_are_listed_with_their_kind() {
    let run = r2s("is");
    assert!(run.ok, "{}", run.out);
    assert!(
        run.out.contains("GLOBAL FUNC   54       fnv1a32"),
        "{}",
        run.out
    );
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
    // `afl` is radare2's layout; how sure discovery is lives in `aflj`.
    let run = r2s("aflj");
    assert!(run.ok, "{}", run.out);
    let rows: Vec<serde_json::Value> = serde_json::from_str(run.out.trim()).expect("aflj is JSON");
    assert!(!rows.is_empty(), "{}", run.out);
    for row in &rows {
        let confidence = row["confidence"].as_str().unwrap_or_default();
        assert!(
            ["stated", "called", "handed", "reached"].contains(&confidence),
            "no confidence on {row}"
        );
        assert!(
            row["addr"].is_u64() && row["nbbs"].is_u64() && row["size"].is_u64(),
            "{row}"
        );
    }
    // Discovery may not lose a function the format states outright: every
    // one the symbol table defines, which excludes the imports it lists.
    let defined = r2s("is~FUNC~!imp.?").out;
    let defined: usize = defined.trim().parse().expect("a count");
    assert!(rows.len() >= defined, "{}", run.out);
}

/// The stripped `rv` binary's `fcn_12ef` writes RAX and XMM0, and its one caller reads XMM0: a
/// fresh `pdd` reads the body alone, which leaves the result open; after `aa`, the call decides it.
#[test]
fn aa_reads_each_functions_callers() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rv_O0g_stripped");
    let alone = on(fixture.clone(), "pdd @ 0x12ef");
    assert!(alone.ok, "{}", alone.out);
    assert!(
        alone.out.contains("return r2sleigh_residual_"),
        "{}",
        alone.out
    );
    let analysed = on(fixture.clone(), "aa; pdd @ 0x12ef");
    assert!(analysed.ok, "{}", analysed.out);
    assert!(
        analysed.out.starts_with("double fcn_12ef("),
        "{}",
        analysed.out
    );
    assert!(
        !analysed.out.contains("r2sleigh_residual"),
        "{}",
        analysed.out
    );
    assert_eq!(on(fixture, "aa").out, "");
}

/// `aa` surveys the program, which needs its machine: an ELF whose machine has no Sleigh
/// description is refused, and the shell says so.
#[test]
fn aa_refuses_a_machine_it_cannot_decode() {
    let mut bytes = std::fs::read(fixture()).expect("the fixture");
    bytes[18..20].copy_from_slice(&22u16.to_le_bytes()); // e_machine: EM_S390
    let dir = std::env::temp_dir().join(format!("r2s-aa-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temporary directory");
    let binary = dir.join("s390.elf");
    std::fs::write(&binary, bytes).expect("write the binary");
    let run = on(binary, "aa");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!run.ok, "{}", run.out);
    assert!(
        run.out.contains("this build decodes no s390x code"),
        "{}",
        run.out
    );
}

/// `afl` is radare2's: no header, then `addr nbbs size name`, the size being
/// the bytes of the blocks and not the span with the padding between them.
/// gcc's `deregister_tm_clones` ends in a `jmp rax` with its `ret` eight
/// bytes on: four blocks, 34 bytes, which is exactly radare2's row. `_start`
/// ends at `call [__libc_start_main]`: the slot's import is declared never to
/// return, so the `hlt` after it is no block of the body.
#[test]
fn afl_lists_functions_in_radare2s_columns() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rv_O0g");
    let run = on(fixture, "afl");
    assert!(run.ok, "{}", run.out);
    assert!(
        run.out.lines().all(|row| row.starts_with("0x")),
        "{}",
        run.out
    );
    for row in [
        "0x000010c0    1     37 sym._start",
        "0x000010f0    4     34 sym.deregister_tm_clones",
        "0x000011c1    4     73 sym.sum_array",
        "0x00001549    6    640 sym.main",
    ] {
        assert!(
            run.out.lines().any(|line| line == row),
            "{row}\n{}",
            run.out
        );
    }
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
    // The loop guard tests the shifted length itself, against zero.
    let shifted = run
        .out
        .lines()
        .find_map(|line| {
            let (assigned, value) = line.trim().split_once(" = ")?;
            let assigned = assigned.rsplit(' ').next()?;
            value.contains(">>").then(|| assigned.to_owned())
        })
        .unwrap_or_else(|| panic!("no shift: {}", run.out));
    assert!(
        run.out.lines().any(|line| {
            let line = line.trim();
            line.starts_with("if (")
                && line
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .any(|word| word == shifted)
                && (line.contains("!= ") || line.contains("== "))
                && line.contains('0')
        }),
        "{shifted} decides no branch: {}",
        run.out
    );
    // No flag is read, however a pipeline spells it (`ZF`, `CF_0`, `cf_2`).
    let flags = run
        .out
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| {
            let word = word.to_ascii_lowercase();
            let (register, version) = word.split_once('_').unwrap_or((&word, ""));
            let versioned = !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit());
            match register {
                "zf" | "cf" | "pf" | "sf" => version.is_empty() || versioned,
                "of" => versioned,
                _ => false,
            }
        })
        .collect::<Vec<_>>();
    assert!(flags.is_empty(), "{flags:?} read by {}", run.out);
}

#[test]
fn the_ledger_says_what_the_function_owes_and_whether_it_paid() {
    // The counts behind `pdd`'s proof line, which used to reach only a file
    // behind an environment variable.
    let run = r2s(&format!("s {FNV1A32}; pddo"));
    assert!(run.ok, "{}", run.out);
    for column in [
        "total=",
        "rendered=",
        "elided=",
        "refused=",
        "residual=",
        "unaccounted=",
    ] {
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
    let c = r2s(&format!("s {FNV1A32}; pdd"));
    for run in [&low, &c] {
        assert!(run.ok, "{}", run.out);
        assert!(!run.out.trim().is_empty());
    }
    assert!(low.out.contains("Entry: 0x401330"), "{}", low.out);
    assert!(c.out.contains("fnv1a32("), "{}", c.out);
    assert_ne!(low.out, c.out);
}

/// The low tier lifts the body `afb` lists: a dispatch's arms are blocks of it, and a block starts and
/// ends where `afb` and `pd` say, whatever the function holds.
#[test]
fn pdil_lists_the_blocks_afb_lists() {
    let listing = r2s("afl");
    let entries = (listing.out.lines())
        .filter_map(|line| line.split_whitespace().next())
        .filter(|at| at.starts_with("0x"))
        .collect::<Vec<_>>();
    assert!(entries.len() > 20, "{}", listing.out);
    let script = (entries.iter())
        .map(|at| format!("?e ENTRY {at}; pdil @ {at}; ?e AFB; afb @ {at}"))
        .collect::<Vec<_>>()
        .join("; ");
    let run = r2s(&script);
    assert!(run.ok, "{}", run.out);
    let mut dispatching = 0;
    let out = format!("\n{}", run.out);
    for part in out.split("\nENTRY ").skip(1) {
        let (entry, rest) = part.split_once('\n').expect("an entry line");
        let (low, listed) = rest.split_once("AFB\n").expect("both commands answered");
        let lowered = (low.lines())
            .filter_map(|line| line.strip_prefix("Block "))
            .map(|line| {
                let (start, size) = line.split_once(" (").expect("a block header");
                let size = size.split_once(" bytes").expect("a size").0;
                (start.to_owned(), size.parse::<u64>().expect("a size"))
            })
            .collect::<std::collections::BTreeSet<_>>();
        let blocks = (listed.lines())
            .map(|line| line.split_whitespace().collect::<Vec<_>>())
            .filter(|fields| fields.len() > 2 && fields[0].starts_with("0x"))
            .map(|fields| {
                let start = u64::from_str_radix(&fields[0][2..], 16).expect("a start");
                (
                    format!("{start:#x}"),
                    fields[2].parse::<u64>().expect("a size"),
                )
            })
            .collect::<std::collections::BTreeSet<_>>();
        dispatching += usize::from(listed.contains(" s 0x"));
        assert_eq!(lowered, blocks, "the blocks of {entry}:\n{low}\n{listed}");
    }
    assert!(dispatching > 0, "no function of the fixture dispatches");
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
    // can write. They cannot drift because they are the same entry. The
    // interpreter's path this once listed is the loader's, in `.interp`,
    // which the container states is no data of the program's.
    let review = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rv_O0g");
    let listed = on(review.clone(), "iz");
    assert!(listed.ok, "{}", listed.out);
    assert!(listed.out.contains("hello global"), "{}", listed.out);
    assert!(!listed.out.contains("/lib64/ld-linux"), "{}", listed.out);
    let flagged = on(review, "f~str.hello");
    assert!(flagged.ok, "{}", flagged.out);
    assert!(flagged.out.contains("str.hello_global"), "{}", flagged.out);
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

/// The staged pipeline passes each value in the class its register says: `store(double x,
/// double *p)` takes `x` in a float register and writes its bits, and a tail call is no return.
#[test]
fn the_staged_pipeline_keeps_register_classes_and_tail_calls() {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/float_calls_zig_x86_64_O2g");
    let staged = on(
        binary,
        "pdd @ sym.store; pdd @ sym.call_store; pdd @ sym.forward",
    );
    // Each parameter is declared as DWARF states it, by its name: the pointer is read as its word
    // where it is stored through, and passed as itself where the callee declares it the same type.
    // `forward`'s `x + 1.0` adds the double whose bits the constant is, never the integer those bits
    // spell.
    for line in [
        "void store(double x, double* p)",
        "r2sleigh_store_u64((void*)(uint64_t)p, (uint64_t)r2sleigh_float_to_bits_64(x + x));",
        "void forward(double x, double* p)",
        "void store(double, double*);",
        "store(x, p);",
        "store(x + r2sleigh_float_from_bits_64((uint64_t)0x3ff0000000000000U), p);",
    ] {
        assert!(staged.out.contains(line), "{line}: {}", staged.out);
    }
    // `call_store` ends in `jmp store`: the tail call is written, then the `return` it makes, never
    // a bare `return` that would drop it.
    let call_store = staged
        .out
        .split("void call_store")
        .nth(1)
        .expect("call_store renders");
    let call_store = call_store
        .split("void forward")
        .next()
        .unwrap_or(call_store);
    let call = call_store
        .find("store(r2sleigh_float_from_bits_64((uint64_t)0x3ff4000000000000U), p);")
        .expect("the tail call");
    let returned = call_store.find("return;").expect("its return");
    assert!(call < returned, "{call_store}");
    assert!(!call_store.contains("r2sleigh_residual"), "{call_store}");
}

/// `_init`'s call through the `__gmon_start__` pointer is a residual naming whom and why, never
/// `((uint64_t(*)(void))rax_1)()`: no arity from the registers written (audit D3, M3).
#[test]
fn an_indirect_call_nothing_describes_is_a_residual() {
    let staged = r2s("pdd @ 0x401000");
    assert!(!staged.out.contains("(*)("), "{}", staged.out);
    assert!(
        staged.out.contains(
            "r2dec gap: CallNotRendered at 0x401014:4 covering 1 op (render::values): call to an \
             indirect target: no arity is stated, only the registers written before it */"
        ),
        "{}",
        staged.out
    );
    let answer: serde_json::Value =
        serde_json::from_str(r2s("pddj @ 0x401000").out.trim()).expect("pddj is JSON");
    let residuals = answer["residuals"].as_array().expect("residuals");
    let call = (residuals.iter())
        .find(|residual| residual["gap"] == "CallNotRendered")
        .expect("the call's gap");
    assert_eq!(call["callee"], "indirect", "{call}");
    assert_eq!(call["reason"], "count-from-registers", "{call}");
}

/// siphash24's tail switch dispatches through a table on `len & 7`, a value only the elided
/// dispatch reads: the `switch` still reads it, so it is computed, never a residual.
#[test]
fn a_staged_table_switch_reads_its_selector() {
    let staged = r2s("pdd @ 0x4018b0");
    assert!(staged.out.contains("& (uint32_t)7U);"), "{}", staged.out);
    assert!(
        !staged.out.contains("switch (r2sleigh_residual"),
        "{}",
        staged.out
    );
}

/// `shape_variadic`'s last `snprintf` passes eight arguments, two of them in the outgoing stack
/// area: the staged call takes them in order, as integer bits, where it was a gap.
#[test]
fn a_staged_call_passes_its_stack_arguments() {
    let pinned = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/coverage/pinned");
    let staged = on(pinned.join("shapes_gcc_x64_O0"), "pdd @ sym.shape_variadic");
    assert!(
        staged
            .out
            .contains("tmp_40133c_8_1, tmp_401335_8_1, rax_45, tmp_401320_8_1, rax_42);"),
        "{}",
        staged.out
    );
    assert!(!staged.out.contains("CallNotRendered"), "{}", staged.out);
}

/// `sext` takes `int8_t` in DIL and rebuilds RDI from it: the bytes above are what RDI held at
/// entry, which no parameter admits, so they read as a residual where the statement was a gap.
#[test]
fn a_staged_register_held_from_entry_reads_as_a_residual() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let staged = on(fixtures.join("rv_O0g"), "pdd @ sym.sext");
    assert!(
        staged
            .out
            .contains("r2sleigh_residual_u64(1) & (uint64_t)-0x100)"),
        "{}",
        staged.out
    );
    assert!(!staged.out.contains("TermNotSpelled"), "{}", staged.out);
}

/// `_init`'s stack pointer chain (the frame's `sub`/`add rsp` and the call's push) is return
/// control, which the certificates elide: no obligation goes unanswered.
#[test]
fn a_staged_ledger_elides_what_the_certificates_elide() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let staged = on(fixtures.join("rv_O0g"), "pdd @ sym._init");
    assert!(
        staged
            .out
            .contains("22 source obligations: 8 rendered, 10 elided, 0 refused, 4 residual;"),
        "{}",
        staged.out
    );
}

/// `mixed_from` returns a two-word struct in RAX and RDX, and its caller reads RDX: the call takes
/// the pair and assigns the half the caller reads, where it read a residual before.
#[test]
fn a_call_taking_a_pair_assigns_the_half_its_caller_reads() {
    let pinned = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/coverage/pinned");
    let staged = on(
        pinned.join("shapes_gcc_x64_O0"),
        "pdd @ sym.shape_struct_value",
    );
    for line in [
        "pair_401984 = mixed_from(arg0, arg1);",
        "rdx_2 = (uint64_t)((__uint128_t)pair_401984 >> 64U);",
        "mixed_fold(tmp_401991_8_1, rdx_2);",
    ] {
        assert!(staged.out.contains(line), "{line}: {}", staged.out);
    }
    assert!(!staged.out.contains("r2sleigh_residual"), "{}", staged.out);
}

/// zig's `main` truncates a double to `int32_t` (`cvttsd2si`): in range it is the cast, out of
/// range C leaves it undefined, so that arm is a residual.
#[test]
fn a_staged_float_truncation_is_guarded_by_its_range() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let staged = on(
        fixtures.join("float_moves_zig_x86_64_O2g"),
        "pdd @ 0x01001510",
    );
    assert!(staged.out.contains("> -2147483649.0 && "), "{}", staged.out);
    assert!(
        staged.out.contains(" < 2147483648.0 ? (int32_t)"),
        "{}",
        staged.out
    );
    assert!(
        staged.out.contains(" : r2sleigh_residual_i32("),
        "{}",
        staged.out
    );
    // The return's obligations are residual on the proof line, as its text is.
    assert!(
        staged
            .out
            .contains("19 rendered, 9 elided, 0 refused, 2 residual"),
        "{}",
        staged.out
    );
}

/// A tail call returns what its callee leaves in the function's own result register: RAX for
/// `frame_dummy`, XMM0 for `swap_call`, whose arguments it swaps first.
#[test]
fn a_staged_tail_call_returns_its_callee_s_result() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    for (binary, function, line) in [
        ("rv_O0g", "sym.frame_dummy", "return register_tm_clones();"),
        (
            "float_moves_zig_x86_64_O2g",
            "sym.swap_call",
            "return scale(b, a);",
        ),
    ] {
        let staged = on(fixtures.join(binary), &format!("pdd @ {function}"));
        assert!(staged.out.contains(line), "{line}: {}", staged.out);
        assert!(!staged.out.contains("r2sleigh_residual"), "{}", staged.out);
    }
}

/// A staged control residual says why in `pddj` (an untargeted `jmp rax`, an unproven return),
/// and the proof counts no residual the text does not hold. `__do_global_dtors_aux`'s calls to
/// floors past their floor are gaps beside its unproven returns (audit W7).
#[test]
fn a_staged_control_residual_states_its_cause() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    for (binary, function, cause, gap) in [
        (
            "rv_O2",
            "sym.dispatch",
            "gap",
            Some("UnresolvedIndirectBranch"),
        ),
        (
            "rv_O0g",
            "sym.__do_global_dtors_aux",
            "unproven-return",
            None,
        ),
    ] {
        let staged = on(fixtures.join(binary), &format!("pddj @ {function}"));
        let answer: serde_json::Value =
            serde_json::from_str(staged.out.trim()).expect("pddj is JSON");
        let residuals = answer["residuals"].as_array().expect("residuals");
        assert!(!residuals.is_empty(), "{function}: {answer}");
        let stated = |residual: &&serde_json::Value| {
            residual["cause"] == cause && residual["gap"].as_str() == gap
        };
        assert!(residuals.iter().any(|r| stated(&r)), "{function}: {answer}");
        for residual in residuals.iter().filter(|r| !stated(r)) {
            assert_eq!(residual["cause"], "gap", "{function}: {residual}");
            assert!(residual["gap"].is_string(), "{function}: {residual}");
        }
    }
}

/// A staged constant a prototyped parameter holds passes as itself: `main`'s calls in the review
/// fixture, where only `printf`'s variadic tail keeps its conversions.
#[test]
fn a_staged_constant_argument_is_the_constant() {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rv_O0g");
    let staged = on(binary, "pdd @ sym.main");
    for call in ["bit_count(0xf0f0)", "fact(5)", ", 16);", ", 16, 7);"] {
        assert!(staged.out.contains(call), "{call}: {}", staged.out);
    }
    assert!(
        staged.out.contains("printf(\"%d %s\\n\", (uint64_t)"),
        "{}",
        staged.out
    );
}

/// Stripped `avg` writes RAX (its loop test) and XMM0 (its double); after `aa`, its caller's `movsd`
/// of XMM0 says which is the result. Vectorized `crc32_init` writes both, no call reads either.
#[test]
fn a_body_writing_both_result_registers_returns_what_its_callers_read() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let avg = on(
        root.join("tests/fixtures/rv_O0g_stripped"),
        "aa; pdd @ 0x12ef",
    );
    assert!(avg.out.starts_with("double fcn_12ef("), "{}", avg.out);
    assert!(!avg.out.contains("r2sleigh_residual"), "{}", avg.out);
    let unread = on(
        root.join("tests/coverage/pinned/hashes_gcc_x64_O2"),
        "aa; pdd @ sym.crc32_init",
    );
    assert!(
        unread.out.contains("return r2sleigh_residual_u64("),
        "{}",
        unread.out
    );
}

/// The library table says `__libc_start_main` takes functions (`func`) it gives no parameters for:
/// each is spelled `void(*)()`, a type C accepts, where it was `/* unknown */*`, which none does.
#[test]
fn an_import_stub_spells_a_function_its_declaration_gives_no_parameters() {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/float_calls_zig_aarch64_O2g");
    let run = on(binary, "pdd @ 0x01010640");
    assert!(
        run.out.contains(
            "extern int32_t __libc_start_main(void(*)(), int32_t, char**, void(*)(), void(*)(), void(*)(), void*);"
        ),
        "{}",
        run.out
    );
    assert!(!run.out.contains("unknown"), "{}", run.out);
}

/// A double comes back in XMM0's low lane: the call's result is its bits, the rest of the register
/// zero, and the return reads the lane back.
#[test]
fn a_staged_call_returns_a_float_in_its_register_s_low_lane() {
    let binary =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/two_units_O0g");
    let staged = on(binary, "pdd @ sym.from_b");
    for line in [
        "double from_b(const double* values, int64_t count)",
        "double helper(const double*, int64_t);",
        "xmm0_1 = (__uint128_t)r2sleigh_float_to_bits_64(helper(values, count));",
        "return (double)r2sleigh_float_from_bits_64((uint64_t)xmm0_1);",
    ] {
        assert!(staged.out.contains(line), "{line}: {}", staged.out);
    }
}

/// `fill` stores `g_table[i]` at `i * 4 + 0x4040`, the table's exact address plus its index: staged
/// declares the table at its DWARF type and spells the address off it, as the frame spells a computed
/// index off its one array.
#[test]
fn a_staged_computed_index_off_a_named_global_is_spelled_off_that_global() {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rv_O0g");
    let staged = on(binary, "pdd @ sym.fill");
    for line in [
        "extern int32_t g_counter;",
        "extern int32_t g_table[16];",
        " + (uint64_t)&g_table)",
        "2 data object types supplied by the source",
    ] {
        assert!(staged.out.contains(line), "{line}: {}", staged.out);
    }
    assert!(!staged.out.contains("0x4040"), "{}", staged.out);
}

/// A recursive call names the function itself at its own signature: `fact` calls `fact` with
/// no declaration that could contradict the definition, which C rejects.
#[test]
fn a_staged_recursive_call_agrees_with_its_own_definition() {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rv_O0g");
    let staged = on(binary, "pdd @ sym.fact");
    assert!(
        staged.out.contains("int32_t fact(int32_t n)"),
        "{}",
        staged.out
    );
    assert!(
        staged
            .out
            .contains("= (uint64_t)(uint32_t)fact((uint32_t)((uint32_t)n - (uint32_t)1U));"),
        "{}",
        staged.out
    );
    assert!(!staged.out.contains("fact(uint64_t)"), "{}", staged.out);
}

/// The staged pipeline's frame is one array aligned as the machine's (D4): `main` passes `&d`,
/// `sp + 8` on AArch64, where SP is 16-aligned at entry, to two calls and reads it after each.
#[test]
fn the_staged_frame_is_one_array_a_call_may_be_passed_into() {
    let binary = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/float_calls_zig_aarch64_O2g");
    let staged = on(binary, "pdd @ main");
    for line in [
        "_Alignas(16) uint8_t frame[32];",
        "call_store((double*)(uint64_t)(frame + 8U));",
        "(double*)(uint64_t)(frame + 8U));",
    ] {
        assert!(staged.out.contains(line), "{line}: {}", staged.out);
    }
}

/// `pdd` writes certified control, and the hash loop's values render from the sealed facts with
/// no gap.
#[test]
fn pdd_writes_from_the_sealed_facts() {
    let staged = r2s(&format!("pdd @ {FNV1A32}"));
    for line in [
        "return (uint64_t)0x811c9dc5U;",
        "r2sleigh_load_u8((void*)rdi_1)",
        "* (uint64_t)0x1000193U",
    ] {
        assert!(staged.out.contains(line), "{line}: {}", staged.out);
    }
    assert!(!staged.out.contains("r2dec gap"), "{}", staged.out);
    assert!(!staged.out.contains("r2sleigh refused"), "{}", staged.out);
}

/// `e` reads and sets the keys the shell acts on, by radare2's names: a key
/// it lacks and a value it cannot read are refused, and the value stays.
#[test]
fn a_configuration_key_is_read_set_and_refused_by_radare2s_names() {
    let run = r2s("e; e asm.bytes=false; pd 1 @ 0x401330; e asm.bytes=maybe; e asm.bytes");
    assert_eq!(
        run.out,
        "asm.bytes = true\n\
         scr.color = 0\n\
         \x20           0x00401330      endbr64\n\
         false\n\
         r2s: asm.bytes takes true or false, not 'maybe'\n",
    );
    assert!(
        on(fixture(), "e nosuch.key")
            .out
            .contains("Invalid config key nosuch.key")
    );

    // Colour is a setting a grep does not reset: the grep only keeps escapes
    // out of the statement it reads.
    let colour = r2s("e scr.color=1; pd 1 @ 0x401330~endbr; e scr.color");
    assert_eq!(
        colour.out,
        "            0x00401330      f30f1efa       endbr64\n1\n"
    );

    // `-e` sets a key before the script runs, and a bad one ends the shell.
    let flagged = started(
        Command::new(env!("CARGO_BIN_EXE_r2s"))
            .args(["-q", "-e", "scr.color=1", "-c", "pd 1 @ 0x401330"])
            .arg(fixture()),
    )
    .wait_with_output()
    .expect("the shell is waited for");
    assert!(String::from_utf8_lossy(&flagged.stdout).contains("\x1b["));
    let refused = started(
        Command::new(env!("CARGO_BIN_EXE_r2s"))
            .args(["-q", "-e", "asm.byte=1", "-c", "q"])
            .arg(fixture()),
    )
    .wait_with_output()
    .expect("the shell is waited for");
    assert!(!refused.status.success());
}

/// Discovery's walk is held per state of the bytes, so a patch that ends a
/// body early is walked again: the second `afl` of one session sees the `ret`.
#[test]
fn a_patch_is_discovered_again_in_the_same_session() {
    let run = r2s("afl~0x00401330; wx c3 @ 0x401334; afl~0x00401330");
    assert!(run.ok, "{}", run.out);
    let (before, after) = run
        .out
        .split_once("1 bytes at")
        .expect("the write reports what it wrote");
    assert!(before.contains("    5     51 sym.fnv1a32"), "{}", run.out);
    assert!(after.contains("    1      5 sym.fnv1a32"), "{}", run.out);
}

/// A patch moves what the image says about itself, not only what it reads as.
///
/// The import table is *decoded*: which address is a linkage stub, and which
/// import it stands for, comes from lifting the stub and following the slot it
/// reads. So does the set of addresses a body walk may not run past, because
/// the stated starts `is_entry` reads include it. Deriving it once and holding it
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

/// A directory is said to be one, not reported as the OS error reading it gave (audit D14).
#[test]
fn a_directory_is_no_binary() {
    let run = on(fixture().parent().expect("a directory").to_owned(), "i");
    assert!(!run.ok, "{}", run.out);
    assert!(
        run.out.contains("is a directory, not a binary"),
        "{}",
        run.out
    );
    assert!(!run.out.contains("os error"), "{}", run.out);
}

#[test]
fn the_image_reports_what_the_container_states() {
    let run = r2s("i");
    assert!(run.ok, "{}", run.out);
    assert!(run.out.contains("format   elf64\n"), "{}", run.out);
    assert!(run.out.contains("x86"), "{}", run.out);
    // The fixture is C, which its compile units state (LP0), spelled as radare2 does.
    assert!(run.out.contains("lang     c\n"), "{}", run.out);
}

/// What the listing states beyond its text; the listings themselves are golden files in
/// `tests/db/cmd/listing`.
mod listing {
    use super::{Run, on};
    use std::path::PathBuf;

    fn at(fixture: &str, script: &str) -> Run {
        on(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(fixture),
            script,
        )
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
            format
                .ends_with(r#"mov esi, str.fnv1a32______08x_n ; "fnv1a32     %08x\n" (declared)"#),
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

    /// `pdf` folds each block of the walked body across its lines, so the page and its offset are one address and the table load reads it; `pd` folds each line alone.
    #[test]
    fn the_aarch64_function_listing_folds_each_block() {
        let fixture = "tests/fixtures/code_pointer_table_O0";
        let run = at(fixture, "pdf @ sym._table_dispatch");
        assert!(run.ok, "{}", run.out);
        let page = "add x8, x8, 0x0 ; defines x8 = 0x100004000 (folded)";
        assert!(run.out.contains(page), "{}", run.out);
        // The word is a chained fixup dyld rebases to 0x100000400: what the
        // file holds there is the fixup's encoding, and what the container
        // states the loader writes is the address, which is what is said.
        let load = run
            .out
            .lines()
            .find(|line| line.contains("ldr x8, [x8, 0x10]"));
        let loaded =
            "ldr x8, [x8, 0x10] ; [0x100004010:8] loaded 0x100000400 sym._table_op_mul (folded)";
        assert!(
            load.is_some_and(|line| line.ends_with(loaded)),
            "{}",
            run.out
        );
        let read = at(fixture, "axt 0x100004010");
        let named = "sym._table_dispatch 0x100000444 [DATA:r--] ldr x8, [x8, 0x10]\n";
        assert!(read.out.starts_with(named), "{}", read.out);
        let plain = at(fixture, "s 0x100000420; pd 24");
        assert!(!plain.out.contains("0x100004010"), "{}", plain.out);
    }

    /// `bl sym.imp.memcpy` lands on a stub in `__stubs`, which the container
    /// states holds instructions (`S_ATTR_PURE_INSTRUCTIONS`): its first bytes
    /// spell `"0"` only by chance, so no line says a string is there and the
    /// name table names none, as radare2 names none.
    #[test]
    fn a_call_to_a_stub_says_no_text_at_it() {
        let fixture = "tests/fixtures/manual_limits_O0";
        let listed = at(fixture, "pdf @ sym._main");
        assert!(listed.ok, "{}", listed.out);
        let mut lines = listed.out.lines();
        let call = lines.find(|line| line.trim_start().starts_with("0x100000e18"));
        let certified =
            "bl sym.imp.memcpy ; sym.imp.memcpy(arg1@x0, arg2=0x100004008, arg3=0x50) (certified)";
        assert!(
            call.is_some_and(|line| line.ends_with(certified)),
            "{}",
            listed.out
        );
        // No transfer's target is text, whichever function it goes to.
        for line in listed.out.lines() {
            let mnemonic = line.split_whitespace().nth(2).unwrap_or_default();
            if matches!(mnemonic, "b" | "bl") || mnemonic.starts_with("b.") {
                assert!(!line.contains(r#"; ""#), "{line}");
            }
        }
        let one = at(fixture, "pd 1 @ 0x100000e18");
        assert!(
            one.out.trim_end().ends_with("bl sym.imp.memcpy"),
            "{}",
            one.out
        );
        // The stubs are 0x100000fd8 to 0x100000fe4, and the first string is `__cstring`'s at the end of them.
        let strings = at(fixture, "iz");
        assert!(strings.ok, "{}", strings.out);
        // The vaddr column, the third of radare2's `nth paddr vaddr`.
        let listed = strings.out.lines().filter_map(|line| {
            let address = line.split_whitespace().nth(2)?.strip_prefix("0x")?;
            u64::from_str_radix(address, 16).ok()
        });
        let listed = listed.collect::<Vec<_>>();
        assert!(listed.contains(&0x1_0000_0fe4), "{}", strings.out);
        let stubs = 0x1_0000_0fd8..0x1_0000_0fe4;
        assert!(
            !listed.iter().any(|address| stubs.contains(address)),
            "{}",
            strings.out
        );
        let flags = at(fixture, "f");
        let named = flags
            .out
            .lines()
            .filter(|line| line.starts_with("0x100000fd8"));
        let named = named.collect::<Vec<_>>();
        assert!(
            named.iter().any(|line| line.ends_with(" sym.imp.memcpy")),
            "{}",
            flags.out
        );
        assert!(
            !named.iter().any(|line| line.contains(" str.")),
            "{}",
            flags.out
        );
        // The reference index never read the text, and still names the call.
        let refs = at(fixture, "axt 0x100000fd8");
        let call = "sym._main 0x100000e18 [CALL:--x] bl sym.imp.memcpy\n";
        assert!(refs.out.starts_with(call), "{}", refs.out);
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

    /// The entry spills of `x0`/`x1` hold only the parameters, which the frame model proves in the
    /// same preparation (doc/adr-frame-model.md, P4.5): each is its parameter, never a local copy.
    #[test]
    fn a_spilled_parameter_is_its_parameter() {
        let run = r2s("pdd @ sym._table_dispatch");
        assert!(run.ok, "{}", run.out);
        assert!(!run.out.contains("= X0_0;"), "{}", run.out);
        assert!(!run.out.contains("= X1_0;"), "{}", run.out);
    }

    /// A call through a table entry no prototype describes is shown unproven, never cast to the
    /// arity the caller's registers suggest (audit D3); the entries' common prototype is SM's.
    #[test]
    fn a_call_through_a_table_is_shown_unproven() {
        let run = r2s("s 0x100000420; pdd");
        assert!(run.ok, "{}", run.out);
        assert!(run.out.contains("_table_dispatch("), "{}", run.out);
        assert!(!run.out.contains("(*)("), "{}", run.out);
        assert!(run.out.contains("CallNotRendered"), "{}", run.out);
        assert!(run.out.contains("0 refused"), "{}", run.out);
    }

    /// The block counts and the frame are the prepared analysis's, whatever renders
    /// (doc/adr-frame-model.md): the saved `x29`/`x30` pair is frame management; the loop counter,
    /// the accumulator, the table and the homes of `x0`/`x1` are the body's own.
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
            // The loaded table leaves q0 written on the path that skips the loop, so the body does
            // not say whether x0 or v0 is the result, and no returned use makes the arguments unsigned.
            "arg int64_t arg1 @ x0\n\
             arg int64_t arg2 @ x1\n\
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
        // No function is defined in any table; what the dynamic table still
        // states is the imports.
        let run = r2s("is");
        assert!(run.ok, "{}", run.out);
        let functions: Vec<&str> = run
            .out
            .lines()
            .filter(|line| line.contains("FUNC"))
            .collect();
        assert!(!functions.is_empty(), "{}", run.out);
        assert!(
            functions.iter().all(|line| line.contains(" imp.")),
            "{}",
            run.out
        );
    }

    #[test]
    fn main_is_found_because_its_frame_says_so() {
        let run = r2s("aflj");
        assert!(run.ok, "{}", run.out);
        // `main` is at 0x401050 in this build, and nothing calls it directly: its `.eh_frame`
        // entry states it, which outranks the handoff to `__libc_start_main` that also finds it
        // (r2engine `a_function_handed_to_an_import_through_its_slot_is_found_as_handed`).
        let rows: Vec<serde_json::Value> =
            serde_json::from_str(run.out.trim()).expect("aflj is JSON");
        let main = rows
            .iter()
            .find(|row| row["addr"].as_u64() == Some(0x401050))
            .unwrap_or_else(|| panic!("main is found: {}", run.out));
        assert_eq!(main["confidence"], "stated", "{}", run.out);
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

/// `agf` draws the function's blocks with every edge between them: FNV-1a's
/// guard branches to the early return and to the loop, the loop's block
/// latches onto itself, and an address nothing maps is refused.
#[test]
fn a_function_graph_is_drawn_with_its_branches_and_its_loop() {
    let run = r2s(&format!("agf @ {FNV1A32}"));
    assert!(run.ok, "{}", run.out);
    for block in [
        "[0x401330]",
        "[0x401339]",
        "[0x401348]",
        "[0x40135c]",
        "[0x401360]",
    ] {
        assert!(run.out.contains(block), "{block}\n{}", run.out);
    }
    // Five edges into tops (two from the guard, the loop's entry, its exit,
    // and its latch), each ending in an arrow outside a box.
    let arrows = run
        .out
        .lines()
        .map(|row| {
            let row = row.chars().collect::<Vec<_>>();
            (0..row.len())
                .filter(|&at| {
                    let letter = |c: Option<&char>| c.is_some_and(|c| c.is_alphanumeric());
                    row[at] == 'v'
                        && !letter(row.get(at.wrapping_sub(1)))
                        && !letter(row.get(at + 1))
                })
                .count()
        })
        .sum::<usize>();
    assert_eq!(arrows, 5, "{}", run.out);
    let refused = r2s("agf @ 0x999999");
    assert!(!refused.ok, "{}", refused.out);
    assert!(refused.out.contains("nothing mapped"), "{}", refused.out);
}

/// `afb` lists gcc -O0's `classify` block by block as radare2 does: the guard
/// jumps to the default and falls into the dispatch, and the dispatch -- whose
/// index is reloaded from the parameter's home the guard compared -- reaches
/// each of its eight arms.
#[test]
fn the_blocks_of_a_switch_on_a_spilled_parameter_reach_every_arm() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rv_O0g");
    let run = on(fixture, "afb @ 0x120a");
    assert!(run.ok, "{}", run.out);
    let lines = run.out.lines().collect::<Vec<_>>();
    assert_eq!(
        lines[0],
        "0x0000120a 0x0000121b 17 j 0x00001270 f 0x0000121b"
    );
    let arms = lines[1].matches(" s ").count();
    assert!(
        lines[1].starts_with("0x0000121b 0x0000123f 36 "),
        "{}",
        run.out
    );
    assert_eq!(arms, 8, "{}", run.out);
    assert_eq!(lines.len(), 11, "{}", run.out);
}

/// `/as` lists every instruction Sleigh says enters the kernel, in a body the
/// walk reached, with the call its number register proves. A number that
/// comes from a parameter is not proven here, and is listed as `?` rather
/// than dropped; `0f 05` inside `mov $0x50f, %eax` is an immediate, not a
/// call. The binary is stripped, static and links no C library.
#[test]
fn syscalls_are_the_kernel_calls_the_bodies_make() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/syscalls_static_O2");
    let run = on(fixture, "/as");
    assert!(run.ok, "{}", run.out);
    assert_eq!(
        run.out.lines().collect::<Vec<_>>(),
        [
            "0x00401009 ?",
            "0x00401020 getpid",
            "0x00401047 getpid",
            "0x00401089 exit_group",
        ],
        "{}",
        run.out
    );
}

/// `?` is generated from the one verb table dispatch reads, so every verb it
/// lists answers `verb?` with its own usage, public verbs come before the
/// maintainer tier, and a name the table does not hold is still unknown.
#[test]
fn help_lists_the_verbs_dispatch_runs_and_each_answers_its_own_usage() {
    let help = r2s("?");
    assert!(help.ok, "{}", help.out);
    assert!(
        help.out.starts_with("Usage: [cmd][~grep][@addr]"),
        "{}",
        help.out
    );
    let listed = help
        .out
        .lines()
        .filter_map(|line| line.strip_prefix("| "))
        .map(|row| row.split_whitespace().next().expect("a verb").to_owned())
        .collect::<Vec<_>>();
    for verb in ["s", "pd", "pdd", "afl", "axt", "wx", "V", "?e", "w", "pdil"] {
        assert!(
            listed.iter().any(|name| name == verb),
            "{verb} missing from:\n{}",
            help.out
        );
    }
    let maintainer = help
        .out
        .find("\nMaintainer:")
        .expect("a maintainer section");
    assert!(help.out[..maintainer].contains("| pdd "));
    assert!(help.out[maintainer..].contains("| pdil "));
    for verb in &listed {
        let usage = r2s(&format!("{verb}?"));
        assert!(usage.ok, "{verb}?: {}", usage.out);
        assert!(
            usage.out.starts_with(&format!("Usage: {verb}")),
            "{verb}?: {}",
            usage.out
        );
    }
    assert!(r2s("q?").out.contains("aliases: quit exit"));
    let unknown = r2s("zz");
    assert!(!unknown.ok);
}

/// A reader that stops reading ends the shell as SIGPIPE ends radare2 (status 141), with no
/// panic: printing past a closed pipe used to exit 101 (audit W52).
#[test]
fn a_closed_pipe_ends_the_shell_quietly() {
    use std::io::Read;
    let mut child = started(
        Command::new(env!("CARGO_BIN_EXE_r2s"))
            // Twenty listings, past any pipe's buffer, so a write meets the closed end.
            .args(["-q", "-c", &["pd 20000"; 20].join(";")])
            .arg(fixture()),
    );
    let mut first = [0; 64];
    let mut stdout = child.stdout.take().expect("piped");
    stdout.read_exact(&mut first).expect("the listing starts");
    let _closing = SPAWNING.lock().unwrap_or_else(PoisonError::into_inner);
    drop(stdout);
    let done = child.wait_with_output().expect("the shell is waited for");
    let stderr = String::from_utf8_lossy(&done.stderr);
    assert_eq!(done.status.code(), Some(141), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
}

/// A reader gone between prompts ends the shell when the prompt is flushed, not at the next line.
#[test]
fn a_pipe_closed_between_prompts_ends_the_shell_at_the_prompt() {
    use std::io::{Read, Write};
    let mut child = {
        let _spawning = SPAWNING.lock().unwrap_or_else(PoisonError::into_inner);
        (Command::new(env!("CARGO_BIN_EXE_r2s")).arg(fixture()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the shell runs")
    };
    let mut stdout = child.stdout.take().expect("piped");
    let mut seen = Vec::new();
    while !seen.ends_with(b"]> ") {
        let mut byte = [0];
        stdout
            .read_exact(&mut byte)
            .expect("the first prompt is printed");
        seen.push(byte[0]);
    }
    let _closing = SPAWNING.lock().unwrap_or_else(PoisonError::into_inner);
    drop(stdout);
    let mut stdin = child.stdin.take().expect("piped");
    stdin.write_all(b"\n").expect("the shell reads");
    drop(stdin);
    let done = child.wait_with_output().expect("the shell is waited for");
    let stderr = String::from_utf8_lossy(&done.stderr);
    assert_eq!(done.status.code(), Some(141), "{stderr}");
}
