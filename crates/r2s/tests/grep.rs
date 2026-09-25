//! What a script's lines, a statement and its `~` grep do, run as the shell.
//!
//! Every expected output below is what radare2 6.2.3 prints for the same
//! expression over the text r2s spelled (`r2 -q -c 'cat is.txt~EXPR' --` on
//! r2s's own `is` listing), or for the same statement, except where a comment
//! gives radare2's output instead: the cases in
//! `the_rows_count_the_lines_the_grep_kept`, the escaped and quoted `~??` in
//! `the_help_is_the_grammar_the_parser_reads`, and the comma-only grep in
//! `a_grep_reads_each_line_without_its_ansi_escapes`. Each of those is a
//! disagreement the help lists under "where r2s follows the documentation".
//! Where a script writes, only the bytes written are radare2's: the
//! `N bytes at` line and the `wc` listing are r2s's own spelling.

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

/// A GCC-built x86-64 ELF carried in the tree, not stripped.
fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/coverage/pinned/hashes_gcc_x64_O2")
}

struct Run {
    stdout: String,
    stderr: String,
    ok: bool,
}

fn r2s(script: &str) -> Run {
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .args(["-q", "-c", script])
        .arg(fixture())
        .output()
        .expect("the shell runs");
    Run {
        stdout: String::from_utf8_lossy(&done.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&done.stderr).into_owned(),
        ok: done.status.success(),
    }
}

/// Run each script and hold its standard output to the lines given.
fn expect(table: &[(&str, &[&str])]) {
    for (script, lines) in table {
        let run = r2s(script);
        assert!(run.ok, "{script}: {}", run.stderr);
        let wanted = if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n", lines.join("\n"))
        };
        assert_eq!(run.stdout, wanted, "{script}");
    }
}

const CRC32: [&str; 3] = [
    "15  0x00401530   76 FUNC crc32_bitwise",
    "16  0x00401580  170 FUNC crc32_init",
    "17  0x00401630   67 FUNC crc32_table",
];

/// Scripts and the lines each prints: radare2's output for the same grep.
const GRAMMAR: &[(&str, &[&str])] = &[
    // `,` is any word, `&` every word, and `~` another stage.
    (
        "is~fnv1a32,djb2",
        &[
            "9   0x00401330   54 FUNC fnv1a32",
            "11  0x004013b0   54 FUNC djb2",
        ],
    ),
    ("is~&FUNC,crc32", &CRC32),
    ("is~FUNC~crc32", &CRC32),
    (
        "is~!FUNC,OBJ",
        &[
            "nth vaddr      size type name",
            "------------------------------------------------------------",
            "27  0x004022d0    0 NOTY __GNU_EH_FRAME_HDR",
            "33  0x00404008    0 NOTY __data_start",
            "34  0x00404008    0 NOTY data_start",
            "37  0x00404018    0 NOTY _edata",
            "38  0x00404020    0 NOTY __bss_start",
            "41  0x00404440    0 NOTY _end",
        ],
    ),
    // A trailing `$` anchors the end, `^` the start, `+` folds case.
    (
        "is~32$",
        &[
            "9   0x00401330   54 FUNC fnv1a32",
            "13  0x00401420  118 FUNC adler32",
            "14  0x004014a0  142 FUNC fletcher32",
            "18  0x00401680  196 FUNC murmur3_32",
            "19  0x00401750  347 FUNC xxhash32",
        ],
    ),
    (
        "is~+FNV",
        &[
            "9   0x00401330   54 FUNC fnv1a32",
            "10  0x00401370   52 FUNC fnv1a64",
        ],
    ),
    // Counting lines and bytes.
    ("is~FUNC?", &["23"]),
    ("is~FUNC~!crc32?", &["20"]),
    ("is~FUNC~?.", &["826"]),
    // Columns, rows, and both in one stage.
    (
        "is~crc32[4]",
        &["crc32_bitwise", "crc32_init", "crc32_table"],
    ),
    ("is~FUNC:1..3[4]", &["main", "_start"]),
    ("is~FUNC[-2--1]:0", &["FUNC _init"]),
    (
        "is~^1,2~:0..3",
        &[
            "1   0x00401000    0 FUNC _init",
            "2   0x00401050  493 FUNC main",
            "10  0x00401370   52 FUNC fnv1a64",
        ],
    ),
    // Rows before columns count the lines the words kept, so the
    // separator is row 1 and has no column 4; columns before rows count
    // the projected lines (grep.c:354-356, radare2's `range` tests).
    ("is~:1~[4]", &[]),
    ("is~[4]~:1", &["__abi_tag"]),
    // A later row window is taken within the one before.
    ("is~FUNC~:0..2~:1", &["2   0x00401050  493 FUNC main"]),
    // Orders: sort, reverse sort, uniq, tac, and `$:n` keeping lines in place.
    (
        "is~$!crc32[4]",
        &["crc32_table", "crc32_init", "crc32_bitwise"],
    ),
    ("is~$$FUNC[3]", &["FUNC"]),
    ("is~[3]~$$", &["FUNC", "NOTY", "OBJ", "type"]),
    ("is~$!!crc32", &[CRC32[2], CRC32[1], CRC32[0]]),
    (
        "is~crc32,fnv~$:1",
        &[
            "9   0x00401330   54 FUNC fnv1a32",
            "10  0x00401370   52 FUNC fnv1a64",
            CRC32[0],
            CRC32[1],
            CRC32[2],
        ],
    ),
    // Numbers sort by value, after the lines kept in place.
    (
        "is~FUNC[2]~$:3",
        &[
            "0", "493", "38", "0", "0", "0", "0", "0", "5", "43", "51", "52", "54", "54", "67",
            "76", "80", "118", "142", "170", "196", "347", "608",
        ],
    ),
    // Escapes, quotes and separators, as radare2's line reads them.
    ("?e a\\~b", &["a~b"]),
    ("?e \"a~b\"", &["a~b"]),
    ("?e 'a~b'", &["a~b"]),
    ("?e \"a~b\"~a", &["a~b"]),
    ("?e a\\;b", &["a;b"]),
    ("?e x\\@y~x\\@", &["x@y"]),
    ("?e a\\#b~\\#", &["a#b"]),
    // A `?*` just after a `~` is not radare2's recursive help.
    ("?e \"a~?*\" b?*", &["a~?* b?*"]),
    // `\:` is a `:` before the stage's first bare `:`, and words cut at rows
    // that come before the columns are cut where radare2 cuts them.
    ("?e x:y:z~x\\:y:z", &["x:y:z"]),
    ("?e a:b c~a\\:b:0[1]", &["c"]),
    // A stage with no words keeps every line.
    ("?e hello~!", &["hello"]),
    ("?e hello~,", &["hello"]),
    // A negative row or column with a leading 0 is decimal in radare2 too
    // (util/unum.c:460); only an unsigned one is octal there, and refused.
    ("?e a b c d e f g h i j k l~[-010]", &["c"]),
    (
        "is~:-010..-08",
        &[
            "32  0x00403fe8    0 OBJ  _GLOBAL_OFFSET_TABLE_",
            "33  0x00404008    0 NOTY __data_start",
        ],
    ),
];

#[test]
fn the_grep_grammar_selects_what_radare2_selects() {
    expect(GRAMMAR);
}

#[test]
fn a_sort_keeps_the_header_lines_in_place() {
    // `$!:2` over the numbers column: the header and separator stay on top.
    let run = r2s("is~[0]~$!:2");
    assert!(run.ok, "{}", run.stderr);
    let mut wanted = vec!["nth".to_owned(), "-".repeat(60)];
    wanted.extend((0..=41).rev().map(|row: u32| row.to_string()));
    assert_eq!(run.stdout, format!("{}\n", wanted.join("\n")));
}

#[test]
fn the_help_is_the_grammar_the_parser_reads() {
    // Judged: radare2 finds the statement's first `~?` with strstr
    // (cmd.c:5219), here the quoted one, so it counts the line and prints `1`.
    for script in ["is~??", "?e a~a~??", "~?", "?e \"a~?\" b~??"] {
        let run = r2s(script);
        assert!(run.ok, "{script}: {}", run.stderr);
        assert!(run.stdout.starts_with("Usage: [command]~"), "{script}");
        for listed in ["$!!", "?ea", "{", "[n-m]", ":s..e", "word:-n", ":010 [010]"] {
            assert!(
                run.stdout.contains(listed),
                "{script}: `{listed}` missing from {}",
                run.stdout
            );
        }
    }
    // Only a grep asks for the help: an escaped `~` is text. Judged: radare2
    // finds `~??` with strstr and prints the help (cmd.c:5219).
    expect(&[("?e a\\~??", &["a~??"])]);
}

/// Where radare2 contradicts its own documentation, r2s follows the
/// documentation. Each comment gives what radare2 prints instead.
#[test]
fn the_rows_count_the_lines_the_grep_kept() {
    expect(&[
        // radare2 resolves a negative row against every line of the output
        // but indexes the lines the words kept (grep.c:875-896, 959); its help
        // says `i~:-2` is the second to last line. radare2: nothing.
        ("is~FUNC:-1", &["23  0x00401ba0    0 FUNC _fini"]),
        // radare2 clears the count's window after the first line it shows
        // (grep.c:918, 967-969). radare2: `1`.
        ("is~FUNC:0..3?", &["3"]),
        // radare2 projects only the lines inside the row window, so the
        // unprojected header and separator hold rows 0 and 1 (grep.c:1100-1103).
        // radare2: `__abi_tag`.
        ("is~[4]:2", &["_init"]),
        // Rows in a stage before the columns count every line the words
        // kept, so the separator takes row 0 and has no column 4. radare2
        // keeps that order only without words (grep.c:897, 960) and skips the
        // separator: `_init`, `main`, `_start`.
        ("is~--,FUNC~:0..3~[4]", &["_init", "main"]),
        // The same, with the rows in the words' stage. radare2: `0x00401000`,
        // `0x00401050`.
        ("is~-,FUNC:0..2~[1]", &["0x00401000"]),
        // A later window stays within the one before it. radare2 adds the
        // bounds unclipped (grep.c:102-108) and starts at row 3, before it.
        (
            "is~:5..10~:-7..",
            &[
                "3   0x00401240   38 FUNC _start",
                "4   0x00401270    5 FUNC _dl_relocate_static_pie",
                "5   0x00401280    0 FUNC deregister_tm_clones",
                "6   0x004012b0    0 FUNC register_tm_clones",
                "7   0x004012f0    0 FUNC __do_global_dtors_aux",
            ],
        ),
    ]);
    // A start before the first line is clipped to it, so the last 100 rows of
    // a shorter listing are all of it. radare2 shows lines only from reaching
    // the exact start line, which it never reaches (grep.c:880-895, 917):
    // nothing.
    let all = r2s("is");
    let clipped = r2s("is~:-100..");
    assert!(clipped.ok, "{}", clipped.stderr);
    assert!(all.stdout.lines().count() > 40);
    assert_eq!(clipped.stdout, all.stdout);
}

#[test]
fn an_unsupported_grep_is_refused_before_the_command_runs() {
    for grep in [
        "{}",
        "{sym}",
        "{=}",
        "..",
        "...",
        ":)",
        ":}",
        "<>",
        "<50",
        "<b",
        "*x",
        "?ea",
        "?~??x",
        "$2",
        "$$:1",
        "$!!:1",
        // radare2 reads the second `$` of `$$` again, so this `!` is an
        // order, not a negation.
        "$$!",
        "$$!!",
        "$$!FUNC",
        "$:",
        // radare2 truncates rows and `$:n` to 32 bits.
        ":4294967297",
        "$:4294967298",
        // radare2 evaluates `[0]` as the end of the rows, a memory read.
        ":2..[0]",
        // radare2 reads a leading 0 as octal: `:010` is row 8 and `[010]`
        // column 8 there, and `:08` is row 0.
        ":010",
        "[010]",
        ":1..010",
        "[1-010]",
        ":08",
        "[rax]",
        "[99]",
        "[+4]",
        "[2]x",
        ":0x",
        "\\,",
        "\\$",
        "\\~",
        "\\<5",
        // radare2 keeps the backslash of a `\:` after a bare `:`, and cuts
        // words that end at columns a character late for each `\:` before.
        "x:y\\:z",
        "a\\:b[1]",
        "$~$!",
        "$imp:0..3",
        ":5..2",
        "?.~?",
        "a~b~c~d~e~f~g~h~i~j",
        // radare2 reads rows only at the stage's first bare `:`, text in
        // these, and drops what follows the `]`: `?e x:y a\nx:y b~x:y[1]:1`
        // prints `a` and `b` there.
        "x:y[1]:1",
        "std::s[1]:0",
        ":[1]:1",
        // A `]` before the first `[`: radare2 reads no columns and takes the
        // `[1]` into the rows' bound, so `a]:0[1]` prints the whole line.
        "a]:0[1]",
        "]:1..3[1]",
    ] {
        let run = r2s(&format!("s 0x401330; wx 90~{grep}; wc~patched"));
        assert!(!run.ok, "~{grep} was not refused");
        assert!(run.stderr.contains("r2s: grep:"), "~{grep}: {}", run.stderr);
        // The write never ran.
        assert_eq!(run.stdout, "0 patched bytes\n", "~{grep}");
    }
    // A trailing backslash would escape the `;` after it, so it is tried at
    // the end of the script: radare2 drops it and prints `ab`.
    let run = r2s("?e ab~b\\");
    assert!(!run.ok);
    assert!(run.stderr.contains("r2s: grep:"), "{}", run.stderr);
    assert_eq!(run.stdout, "");
}

#[test]
fn what_radare2_reads_as_an_operator_is_refused_before_it_runs() {
    for statement in [
        "wx 90|cat",
        "wx 90>patch.bin",
        "wx `?e 90`",
        "wx $(?e 90)",
        "wx 90 && ?e done",
        "wx 90\\\\;",
        // A macro runs to the first `;` outside its parentheses: radare2
        // defines it and runs none of its body.
        "(m;wx 90;?e x)",
        "2(m;wx 90)",
        // radare2's `@addr@command` prefix.
        "@0x401330@wx 90",
        // radare2's recursive help, found as written wherever no `~` comes
        // just before it; it runs no `wx`.
        "wx 90?*",
        "wx 90~a?*",
    ] {
        let run = r2s(&format!("s 0x401330; {statement}; wc~patched"));
        assert!(!run.ok, "{statement} was not refused");
        assert!(
            run.stderr.contains("r2s: line:"),
            "{statement}: {}",
            run.stderr
        );
        assert_eq!(run.stdout, "0 patched bytes\n", "{statement}");
    }
    // radare2 reads the rest of the line some other way after a comment
    // (`;` included), a malformed prefix, a repeat count with no command or a
    // command that starts with a quote, so nothing after them runs.
    for statement in [
        "?e a#b",
        "@0x401330 wx 90",
        "1",
        "@0x401330@2",
        "\"wx 90\"",
        "'wx 90'",
        "2 \"wx\"(m;?e y)",
    ] {
        let run = r2s(&format!("?e before; {statement}; wx 90; wc~patched"));
        assert!(!run.ok, "{statement} was not refused");
        assert!(
            run.stderr.contains("r2s: line:"),
            "{statement}: {}",
            run.stderr
        );
        assert_eq!(run.stdout, "before\n", "{statement}");
    }
}

/// radare2 hands a handler its command as written, and only `?e` and `w` read
/// a quote or an escape in their argument; every other handler takes one as
/// text. There, radare2 reports `"90"` as bad hex and `"main"` as no name,
/// but reads `'main'` as the number 0x6d, so r2s refuses them all before
/// anything runs rather than take any of them as text.
#[test]
fn a_quote_or_an_escape_is_read_only_where_radare2_reads_one() {
    for statement in [
        // In the verb.
        "w\"x\" 90",
        "w'x' 90",
        // In an argument.
        "wx \"90\"",
        "wx '90'",
        "wx 9\\;0",
        "s \"main\"",
        "s 'main'",
        "s ma\\;in",
        "px \"4\"",
        "pd '1'",
        "pdf \"main\"",
        "afi 'main'",
        "afv \"main\"",
        "axt \"main\"",
        // In the `@` address.
        "wx 90 @ \"0x401350\"",
        "pd 1 @ 'main'",
        "px 4 @ ma\\@in",
    ] {
        let run = r2s(&format!("s 0x401330; {statement}; s; wc~patched"));
        assert!(!run.ok, "{statement} was not refused");
        assert!(
            run.stderr.contains("r2s: line:"),
            "{statement}: {}",
            run.stderr
        );
        // Nothing moved the cursor, nothing was written, nothing was printed.
        assert_eq!(run.stdout, "0x401330\n0 patched bytes\n", "{statement}");
    }
}

/// `?e` and `w` read quotes and escapes as radare2's handlers do: `?e` prints
/// its words joined by one space, a quoted blank kept, and `w` writes its text
/// with the escapes of `r_str_unescape`, a quoted leading blank kept.
#[test]
fn echo_and_write_read_quotes_and_escapes_as_radare2_does() {
    expect(&[
        ("?e \" hi\"", &[" hi"]),
        ("?e \"a\" 'b'", &["a b"]),
        ("?e a   b", &["a b"]),
        ("?e a\\tb", &["a\tb"]),
        ("?e a\\nb~b", &["b"]),
        // An empty line is a line: `?e` prints it, and so does a grep that
        // keeps one.
        ("?e \"\"", &[""]),
        ("?e", &[""]),
        ("?e \\0", &[""]),
        ("?e a\\n\\nb~:1", &[""]),
        ("?e \\e[0m~:0", &[""]),
    ]);
    let run = r2s("s 0x401330; w \" hi\"; wc");
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(
        run.stdout,
        "3 bytes at 0x401330\nvaddr      byte\n----------------\n0x00401330 20\n\
         0x00401331 68\n0x00401332 69\n\n3 patched bytes\n"
    );
    // A quoted blank at the end is dropped, as radare2's `w` drops it, and
    // `\n` is a newline.
    let run = r2s("s 0x401330; w \"h\\ni \"; wc~0x0040");
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(
        run.stdout,
        "3 bytes at 0x401330\n0x00401330 68\n0x00401331 0a\n0x00401332 69\n"
    );
}

/// radare2's grep search drops the backslash of an unquoted `\~` and resumes
/// one character past the `~` (grep.c:381-382), so a `~`, a `\` or a quote
/// right there is text to it. r2s refuses such a statement before it runs.
/// radare2 writes `a~~b` for the first `w` below, and `a~"b` for the second,
/// whose grep is `c"`; it prints `~~a`, `a~"b~b` and `x~\` for the `?e`s.
#[test]
fn an_escaped_tilde_is_refused_where_radare2_skips_what_follows_it() {
    for statement in ["w a\\~~b", "w a\\~\"b~c\""] {
        let run = r2s(&format!("s 0x401330; {statement}; wc~patched"));
        assert!(!run.ok, "{statement} was not refused");
        assert!(
            run.stderr.contains("r2s: line:"),
            "{statement}: {}",
            run.stderr
        );
        assert_eq!(run.stdout, "0 patched bytes\n", "{statement}");
    }
    for script in ["?e \\~~a", "?e a\\~\\\"b~b", "?e x\\~\\~"] {
        let run = r2s(script);
        assert!(!run.ok, "{script} was not refused");
        assert!(
            run.stderr.contains("r2s: line:"),
            "{script}: {}",
            run.stderr
        );
        assert_eq!(run.stdout, "", "{script}");
    }
    // A quoted `\~` is not searched, and any other character after an
    // unquoted one is read the same by both.
    expect(&[
        ("?e \"a\\~~b\"", &["a~~b"]),
        ("?e 'a\\~~b'", &["a~~b"]),
        ("?e a\\~xb~b", &["a~xb"]),
    ]);
    let run = r2s("s 0x401330; w a\\~b; wc~0x0040");
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(
        run.stdout,
        "3 bytes at 0x401330\n0x00401330 61\n0x00401331 7e\n0x00401332 62\n"
    );
}

/// radare2 greps each line without its ANSI escapes, and prints it so
/// (grep.c:907-912); without a grep it prints the escapes as spelled.
#[test]
fn a_grep_reads_each_line_without_its_ansi_escapes() {
    expect(&[
        ("?e a\\eb", &["a\x1bb"]),
        ("?e a\\e~a", &["a"]),
        ("?e a\\eb~&", &["a"]),
        ("?e a\\x1bb~b", &[]),
        ("?e a\\e[31mred\\e[0m~red", &["ared"]),
        ("?e \"x\\e#abcqz\"~z", &["xz"]),
        ("?e a\\e[0mb~?.", &["3"]),
        ("?e b\\e[0m\\na~$", &["a", "b"]),
        // A line the escapes leave empty is blank.
        ("?e \\e[0m~!zz", &[]),
        // Judged (`,  ,:1`): words that are only commas select every line,
        // read as any grep reads it. radare2 runs no grep then, and prints
        // `a\x1b[0mb`.
        ("?e a\\e[0mb~,", &["ab"]),
    ]);
    // An escape that takes the first byte of a longer character with it leaves
    // radare2 printing the rest of the character, `a\xa9b`, which is not text.
    let run = r2s("?e a\\e\u{e9}b~a");
    assert!(!run.ok);
    assert!(run.stderr.contains("r2s: grep:"), "{}", run.stderr);
    assert_eq!(run.stdout, "");
}

/// radare2 cuts a script at every LF before it reads anything else, quotes
/// and all (`r_core_cmd_lines`, `run_cmd_context`), and runs each line on its
/// own: a LF is neither a blank nor text in a quote.
#[test]
fn a_script_is_cut_at_every_line_feed_before_anything_else() {
    // radare2 writes the one byte `a`, then runs `wc`.
    let run = r2s("s 0x401330;w a\nwc~0x0040");
    assert!(run.ok, "{}", run.stderr);
    assert_eq!(run.stdout, "1 bytes at 0x401330\n0x00401330 61\n");
    expect(&[
        ("?e a\n?e b", &["a", "b"]),
        ("?e a~a\n?e b", &["a", "b"]),
        ("?e a\r\n\n?e b\n", &["a", "b"]),
    ]);
    // A quote ends with its line: radare2 reports each line's as unterminated.
    let run = r2s("?e \"a\nb\"");
    assert!(!run.ok);
    assert_eq!(run.stdout, "");
    assert_eq!(run.stderr.matches("r2s: line: an unterminated").count(), 2);
    // A quit ends its line; radare2 goes on with the next.
    let run = r2s("?e a;q;?e b\n?e c");
    assert_eq!(run.stdout, "a\nc\n");
}

/// A line radare2 reads whole before it looks for statements is refused
/// whole: one that starts with `|` is a comment and one that starts with
/// `b64:'` a call, so none of its statements runs, and `/*` opens a comment
/// that takes the rest of the script.
#[test]
fn a_line_radare2_reads_whole_is_refused_whole() {
    for script in [
        "s 0x401330\n|x;wx 90\nwc~patched",
        "s 0x401330\nb64:'x';wx 90\nwc~patched",
    ] {
        let run = r2s(script);
        assert!(!run.ok, "{script:?} was not refused");
        assert!(
            run.stderr.contains("r2s: line:"),
            "{script:?}: {}",
            run.stderr
        );
        assert_eq!(run.stdout, "0 patched bytes\n", "{script:?}");
    }
    let run = r2s("?e a\n/*;wx 90\nwx 90\n*/\nwc~patched");
    assert!(!run.ok);
    assert!(run.stderr.contains("r2s: line: `/*`"), "{}", run.stderr);
    assert_eq!(run.stdout, "a\n");
}

/// At the prompt each line is its own script, and a `/*` comment stays open
/// across them up to a line that starts with `*/`, which it takes too:
/// radare2 6.2.3 reading the same lines prints `1` and `b`.
#[test]
fn a_comment_at_the_prompt_runs_to_its_close() {
    use std::io::Write;
    let mut shell = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .arg("-q")
        .arg(fixture())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the shell runs");
    shell
        .stdin
        .take()
        .expect("a prompt")
        .write_all(b"?e 1\n/*\n?e a\n*/ ?e x\n?e b\n")
        .expect("the lines are read");
    let done = shell.wait_with_output().expect("the shell ends");
    assert_eq!(String::from_utf8_lossy(&done.stdout), "1\nb\n");
    let stderr = String::from_utf8_lossy(&done.stderr);
    assert_eq!(stderr.matches("r2s: line:").count(), 3, "{stderr}");
}

/// After a line that failed or quit, radare2 may run the rest of the script
/// as one command, which ends at the first command it does not know: for this
/// script it prints `a` and nothing after the second `]`. r2s cannot tell
/// which failures radare2 reads so, so from then on the first failure ends the
/// script.
#[test]
fn after_a_failed_line_the_first_failure_ends_the_script() {
    let run = r2s("?e a\n]\n]\n?e b");
    assert!(!run.ok);
    assert_eq!(run.stdout, "a\n");
    assert!(
        run.stderr
            .contains("r2s: line: after a line that failed or quit"),
        "{}",
        run.stderr
    );
    // One failure alone does not: radare2 prints `a` and `b`.
    let run = r2s("?e a\n]\n?e b");
    assert_eq!(run.stdout, "a\nb\n");
    assert!(!run.stderr.contains("after a line"), "{}", run.stderr);
}
