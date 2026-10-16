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
        handed.starts_with("sym.main 0x40106c [DATA:---] mov esi, str.fnv1a32______08x_n\n"),
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

/// What one function's `afb` and `pdf` show: its blocks with their switch arms, and each instruction's address and text.
struct Shown {
    blocks: Vec<(u64, u64, Vec<u64>)>,
    lines: Vec<(u64, String)>,
}

fn number(token: &str) -> Option<u64> {
    u64::from_str_radix(token.strip_prefix("0x")?, 16).ok()
}

/// Where a `call rel32`, `jmp rel32` or `jmp rel8` goes, read off the bytes `pdf` prints beside it.
fn direct(address: u64, bytes: &str) -> Option<u64> {
    let byte = |at: usize| u8::from_str_radix(bytes.get(at..at + 2)?, 16).ok();
    let displacement = match byte(0)? {
        0xe8 | 0xe9 if bytes.len() == 10 => {
            let word = [byte(2)?, byte(4)?, byte(6)?, byte(8)?];
            (5, i64::from(i32::from_le_bytes(word)))
        }
        0xeb if bytes.len() == 4 => (2, i64::from(byte(2)? as i8)),
        _ => return None,
    };
    Some(address.wrapping_add_signed(displacement.0 + displacement.1))
}

/// Every `ax` row as `(from, to, role)`, and what `afb` and `pdf` show of each function `afl` lists, from one session.
fn ax_beside_listings(binary: &str) -> (Vec<(u64, u64, String)>, Vec<Shown>) {
    let path = format!("tests/coverage/pinned/{binary}");
    let entries = on(&path, "afl")
        .lines()
        .filter_map(|line| number(line.split_whitespace().next()?))
        .collect::<Vec<_>>();
    let mut script = String::from("ax");
    for entry in &entries {
        script.push_str(&format!(
            "; ?e ==afb; afb @ {entry:#x}; ?e ==pdf; pdf @ {entry:#x}"
        ));
    }
    let out = on(&path, &script);
    let (rows, rest) = out.split_once("==afb").expect("the script prints afb");
    let rows = rows
        .lines()
        .filter_map(|line| {
            let mut tokens = line.split_whitespace();
            let (from, to) = (number(tokens.next()?)?, number(tokens.next()?)?);
            Some((from, to, tokens.next()?.to_owned()))
        })
        .collect();
    let mut shown = Vec::new();
    for function in rest.split("==afb") {
        let (blocks, lines) = function.split_once("==pdf").expect("pdf follows afb");
        let blocks = blocks
            .lines()
            .filter_map(|line| {
                let tokens = line.split_whitespace().collect::<Vec<_>>();
                let (start, end) = (number(tokens.first()?)?, number(tokens.get(1)?)?);
                let arms = tokens[3..]
                    .chunks(2)
                    .filter(|pair| pair[0] == "s")
                    .filter_map(|pair| number(pair[1]))
                    .collect();
                Some((start, end, arms))
            })
            .collect();
        let lines = lines
            .lines()
            .filter_map(|line| {
                let line = line.trim_start();
                let (address, text) = line.split_once(char::is_whitespace)?;
                Some((number(address)?, text.trim_start().to_owned()))
            })
            .collect();
        shown.push(Shown { blocks, lines });
    }
    (rows, shown)
}

type Rows = [(u64, u64, String)];

/// Every direct call and jump `pdf` writes in a function is a row of `ax`.
fn lines_are_rows(binary: &str, rows: &Rows, function: &Shown) {
    for (address, text) in &function.lines {
        // The bytes column, then the mnemonic and its operand.
        let mut tokens = text.split_whitespace();
        let (Some(bytes), Some(mnemonic), operand) = (tokens.next(), tokens.next(), tokens.next())
        else {
            continue;
        };
        let role = match mnemonic {
            "call" => "CALL:--x",
            jump if jump.starts_with('j') => "JUMP:--x",
            _ => continue,
        };
        let to = operand.and_then(number).or_else(|| direct(*address, bytes));
        let held = |to| {
            rows.iter()
                .any(|row| (row.0, row.1, &*row.2) == (*address, to, role))
        };
        assert!(to.is_none_or(held), "{binary}: {address:#x} {text}");
    }
}

/// Every arm `afb` follows from a block is a jump `ax` has from inside it; how many arms.
fn arms_are_rows(binary: &str, rows: &Rows, function: &Shown) -> usize {
    let arms = function
        .blocks
        .iter()
        .flat_map(|(start, end, arms)| arms.iter().map(move |arm| (*start..*end, *arm)));
    let arms = arms.collect::<Vec<_>>();
    for (block, arm) in &arms {
        let held = rows
            .iter()
            .any(|row| block.contains(&row.0) && row.1 == *arm && row.2 == "JUMP:--x");
        assert!(
            held,
            "{binary}: block {:#x} follows an arm to {arm:#x} that ax lacks",
            block.start
        );
    }
    arms.len()
}

/// Every row of `ax` from inside a function's blocks is an instruction its `pdf` lists.
fn rows_are_listed(binary: &str, rows: &Rows, function: &Shown) {
    let inside = |from: &u64| {
        function
            .blocks
            .iter()
            .any(|block| (block.0..block.1).contains(from))
    };
    for (from, to, _) in rows.iter().filter(|row| inside(&row.0)) {
        let listed = function.lines.iter().any(|line| line.0 == *from);
        assert!(
            listed,
            "{binary}: ax has {from:#x} to {to:#x}, which no pdf of its function lists"
        );
    }
}

#[test]
fn ax_holds_what_every_function_shows_of_its_calls_and_jumps() {
    // One body, three views: every direct call and jump `pdf` writes and every arm `afb` follows is a row of `ax`,
    // and every row of `ax` from inside a body is an instruction that body's `pdf` lists.
    let mut arms = 0;
    for binary in [
        "branchy_gcc_x64_O0",
        "hashes_gcc_x64_O2",
        "shapes_gcc_x64_O0",
    ] {
        let (rows, shown) = ax_beside_listings(binary);
        for function in &shown {
            lines_are_rows(binary, &rows, function);
            arms += arms_are_rows(binary, &rows, function);
            rows_are_listed(binary, &rows, function);
        }
    }
    assert!(arms > 0, "the corpus holds a solved dispatch");
}
