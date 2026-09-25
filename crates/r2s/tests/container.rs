//! What the shell says the container states, checked against the platform's own tools.
//!
//! Each fixture is one the repository ships as bytes, and each expectation is
//! what `readelf`, `dyld_info` or radare2 itself says of it, so the shell's
//! spelling is diffable against radare2 and its facts against the format.

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

/// The shell's standard output for one script over one fixture.
fn run(name: &str, script: &str) -> String {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(fixture(name))
        .output()
        .expect("the shell runs");
    assert!(
        done.status.success() || script == "q",
        "`{script}` on {name}: {}",
        String::from_utf8_lossy(&done.stderr)
    );
    String::from_utf8_lossy(&done.stdout).into_owned()
}

/// The rows of a table: the lines after its rule.
fn rows(out: &str) -> Vec<&str> {
    out.lines()
        .skip_while(|line| !line.starts_with("---"))
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .collect()
}

#[test]
fn ir_lists_every_record_with_its_type_offset_and_addend() {
    // `readelf -r rv_O0g`: thirteen, four of them R_X86_64_RELATIVE, which
    // name no symbol and are spelled, as radare2 spells them, by the address
    // they write.
    let out = run("rv_O0g", "ir");
    let rows = rows(&out);
    assert_eq!(rows.len(), 13, "{out}");
    for (vaddr, paddr, target) in [
        ("0x00003da0", "0x00002da0", "0x000011a0"),
        ("0x00003da8", "0x00002da8", "0x00001160"),
        ("0x00004008", "0x00003008", "0x00004008"),
        ("0x00004018", "0x00003018", "0x00002008"),
    ] {
        let row = format!("{vaddr} {paddr} ADD_64 8      {target}");
        assert!(rows.contains(&row.as_str()), "{row} missing:\n{out}");
    }
    assert!(
        rows.contains(&"0x00003fc8 0x00002fc8 SET_64 7     printf"),
        "{out}"
    );
    // In address order, as radare2 lists them.
    let addresses: Vec<&str> = rows.iter().map(|row| &row[..10]).collect();
    assert!(addresses.is_sorted(), "{out}");
}

#[test]
fn ir_never_lists_a_mach_o_stub() {
    // `__stubs` of manual_limits_O0 is code at 0x100000fd8; the bind is in
    // `__got` and the two rebases in `__const`.
    let out = run("manual_limits_O0", "ir");
    let rows = rows(&out);
    assert_eq!(rows.len(), 3, "{out}");
    assert!(!out.contains("0x100000fd8"), "{out}");
    assert!(rows[0].starts_with("0x100004000") && rows[0].ends_with("_memcpy"));
}

#[test]
fn a_stub_flag_is_as_large_as_its_cell_and_a_slot_flag_as_the_word_the_loader_writes() {
    // `.plt.sec` holds four 16-byte cells; each GOT slot is an 8-byte word.
    let stub = run("rv_O0g", "f~sym.imp.printf");
    assert!(stub.contains("    16 sym.imp.printf"), "{stub}");
    let slot = run("rv_O0g", "f~reloc.printf");
    assert!(slot.contains("     8 reloc.printf"), "{slot}");
}

#[test]
fn baddr_is_where_the_first_file_byte_is_mapped() {
    // radare2: 0x100000000 for a Mach-O executable, whose `__TEXT` maps the
    // header; 0x400000 for a non-PIE ELF; zero for a PIE linked at zero. The
    // RVA base `object` reports is zero for both of the first two.
    for (fixture, baddr) in [
        ("code_pointer_table_O0", "0x100000000"),
        ("manual_limits_O2", "0x100000000"),
        ("hashes_gcc_x64_O2_stripped", "0x00400000"),
        ("rv_O0g", "0x00000000"),
    ] {
        let out = run(fixture, "i~baddr");
        assert_eq!(
            out.split_whitespace().nth(1),
            Some(baddr),
            "{fixture}: {out}"
        );
    }
}

#[test]
fn is_states_each_sections_own_permissions_flags_and_identity() {
    // `.comment` is not loaded, so it permits nothing, whatever the segment at
    // its reported address zero permits; a Mach-O section is named with its
    // segment, as `otool` does.
    let elf = run("rv_O0g", "iS~.comment");
    assert!(
        elf.trim_end()
            .ends_with("0x2d ---- 0x30  PROGBITS    .comment"),
        "{elf}"
    );
    let macho = run("manual_limits_O2", "iS");
    assert!(
        macho.contains("-rw- 0x0   REGULAR     __DATA_CONST.__const"),
        "{macho}"
    );
    assert!(macho.contains("CSTRINGS    __TEXT.__cstring"), "{macho}");
}

#[test]
fn is_lists_every_symbol_with_its_binding_and_every_import_at_its_stub() {
    // radare2's `is` on rv_O0g: `completed.0` is a local object in `.bss`,
    // which the file holds no byte of; the imports are the dynamic table's,
    // each at the stub a call to it lands on and as large as that stub's
    // cell. radare2 gives `__gmon_start__` sixteen bytes too, which no stub
    // of it occupies.
    let out = run("rv_O0g", "is");
    for row in [
        "7   ---------- 0x00004020 LOCAL  OBJ    1        completed.0",
        "48  0x00001549 0x00001549 GLOBAL FUNC   640      main",
        "5   0x000010a0 0x000010a0 GLOBAL FUNC   16       imp.printf",
        "6   ---------- ---------- WEAK   NOTYPE 0        imp.__gmon_start__",
    ] {
        assert!(out.lines().any(|line| line == row), "{row} missing:\n{out}");
    }
    // A stripped binary has no static table, and still states its imports.
    let stripped = run("hashes_gcc_x64_O2_stripped", "is");
    assert!(
        stripped
            .lines()
            .any(|line| line == "3   0x00001040 0x00401040 GLOBAL FUNC   16       imp.__printf_chk"),
        "{stripped}"
    );
}

#[test]
fn ie_lists_the_program_entry_and_iee_the_arrays_the_loader_runs_around_it() {
    // `e_entry` is the header field at 0x18; the initialiser and terminator
    // arrays each state one function, in the slots their relative
    // relocations fill.
    let entry = run("rv_O0g", "ie");
    assert_eq!(
        rows(&entry),
        ["0x000010c0 0x000010c0 0x00000018 0x00000018 program"],
        "{entry}"
    );
    let arrays = run("rv_O0g", "iee");
    assert_eq!(
        rows(&arrays),
        [
            "0x00001160 0x00001160 0x00002da8 0x00003da8 fini",
            "0x000011a0 0x000011a0 0x00002da0 0x00003da0 init",
        ],
        "{arrays}"
    );
}

#[test]
fn iz_lists_the_programs_strings_and_none_of_the_loaders_tables() {
    // `.interp`'s path, the build note, `.dynstr`'s names and runs of the
    // unwind tables all read as text; none of them is a string of the
    // program's, and the container states which sections are its data.
    // radare2's own `iz` of this binary, line for line, the newline escaped.
    let out = run("rv_O0g", "iz");
    assert_eq!(
        rows(&out),
        [
            "0   0x00002008 0x00002008 12  13   .rodata ascii hello global",
            "1   0x00002038 0x00002038 6   7    .rodata ascii %d %s\\n",
        ],
        "{out}"
    );
    // `izz` scans every section's bytes, the loader's tables with them.
    let every = run("rv_O0g", "izz");
    assert!(
        every.contains(".interp         ascii /lib64/ld-linux-x86-64.so.2"),
        "{every}"
    );
    assert!(every.contains(".rodata         ascii %d %s\\n"), "{every}");
}

#[test]
fn axt_lists_a_pointer_in_data_by_the_address_the_loader_writes_there() {
    // 0x4018 is `g_msg`, which the loader fills through R_X86_64_RELATIVE
    // with 0x2008, the string it points at; no instruction names 0x2008.
    let out = run("rv_O0g", "axt 0x2008");
    assert!(
        out.lines()
            .any(|line| line.starts_with("(nofunc) 0x4018 [DATA:---]")),
        "{out}"
    );
    assert!(out.contains("1 references to 0x2008"), "{out}");
}
