//! Every function name a listing prints seeks to that function (ROADMAP D574).

#![cfg(feature = "sleigh")]

use std::path::PathBuf;
use std::process::Command;

/// A g++ -O0 x86-64 ELF with a destructor, a throwing function and C++ imports.
const CXX: &str = "tests/fixtures/cxx_try_catch_gcc_x64_O0";

/// The shell's stdout on `CXX` with `asm.demangle` set as given, and whether it succeeded.
fn shell(demangle: bool, script: &str) -> (bool, String) {
    on(CXX, demangle, script)
}

fn on(binary: &str, demangle: bool, script: &str) -> (bool, String) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(binary);
    let done = Command::new(env!("CARGO_BIN_EXE_r2s"))
        .arg("-e")
        .arg(format!("asm.demangle={demangle}"))
        .args(["-q", "-c", script])
        .arg(path)
        .output()
        .expect("the shell runs");
    let out = String::from_utf8_lossy(&done.stdout).into_owned();
    (done.status.success(), out)
}

/// Each row `afl` prints: the address and the name.
fn listed(demangle: bool) -> Vec<(u64, String)> {
    let (ran, out) = shell(demangle, "afl");
    assert!(ran, "{out}");
    out.lines()
        .map(|row| {
            let mut fields = row.split_whitespace();
            let address = fields.next().and_then(|hex| hex.strip_prefix("0x"));
            let address = u64::from_str_radix(address.expect("an address"), 16).expect("hex");
            let name = fields.skip(2).collect::<Vec<_>>().join(" ");
            (address, name)
        })
        .collect()
}

/// Whether the command line carries a name as one argument: radare2's `~`, `;`, `@`, `|`, `>`,
/// quotes, backtick, `#`, `$(` and `&&` are its operators (line.rs, cmd.c:5241-5247).
fn carried(name: &str) -> bool {
    !name.contains(['~', ';', '@', '|', '>', '"', '\'', '`', '#'])
        && !name.contains("&&")
        && !name.contains("$(")
}

/// `s <name>` lands on the function the row names, and `afi` names it the same way, under both
/// settings; a name the command line cannot carry seeks by its flag spelling, which always can.
#[test]
fn every_name_afl_lists_seeks_to_its_function_and_afi_names_it_alike() {
    let flags = listed(false);
    for demangle in [true, false] {
        let rows = listed(demangle);
        assert_eq!(rows.len(), flags.len());
        let shown = |wanted: &str| rows.iter().any(|(_, name)| name == wanted);
        match demangle {
            true => assert!(shown("Guard::~Guard()") && shown("risky(int)"), "{rows:?}"),
            false => assert!(
                shown("sym._ZN5GuardD1Ev") && shown("sym._Z5riskyi"),
                "{rows:?}"
            ),
        }
        // The names the line cannot carry, which seek by their flag until D624.
        let uncarried = (rows.iter())
            .filter(|(_, name)| !carried(name))
            .map(|(_, name)| name.as_str())
            .collect::<Vec<_>>();
        let expected: &[&str] = if demangle { &["Guard::~Guard()"] } else { &[] };
        assert_eq!(uncarried, expected);
        for ((address, name), (flagged, flag)) in rows.iter().zip(&flags) {
            assert_eq!(address, flagged);
            let sought = if carried(name) { name } else { flag };
            assert!(carried(sought), "{flag}");
            let (ran, out) = shell(demangle, &format!("s {sought}; s; afi~name"));
            assert!(ran, "{sought}: {out}");
            let mut lines = out.lines();
            assert_eq!(
                lines.next(),
                Some(format!("{address:#x}").as_str()),
                "{sought}"
            );
            assert_eq!(
                lines.next(),
                Some(format!("name: {name}").as_str()),
                "{sought}"
            );
        }
    }
}

/// A stripped function is listed, referenced and sought as `fcn.%08x`; a spelling no listing
/// prints (`fcn.401330`) is no name.
#[test]
fn an_unnamed_function_has_one_spelling_and_it_seeks() {
    const STRIPPED: &str = "tests/fixtures/hashes_gcc_x64_O2_stripped";
    let (ran, listed) = on(STRIPPED, true, "afl~0x00401330");
    assert!(ran && listed.ends_with("fcn.00401330\n"), "{listed}");
    let (ran, referenced) = on(STRIPPED, true, "axt @ 0x401330");
    assert!(
        ran && referenced.starts_with("fcn.00401050 0x401067 "),
        "{referenced}"
    );
    assert_eq!(
        on(STRIPPED, true, "s fcn.00401330; s"),
        (true, "0x401330\n".to_owned())
    );
    let (ran, out) = on(STRIPPED, true, "s fcn.401330; s");
    assert!(!ran && !out.contains("0x401330"), "{out}");
}

/// `pdfj` keeps the flag spelling in its text and name, as `aflj` and `ao` do, while `pdf` and its
/// header show the demangled name (the round 15 exit wiring).
#[test]
fn pdfj_keeps_the_flag_spelling_where_pdf_demangles() {
    let (ran, json) = shell(true, "pdfj @ sym._Z7guardedi");
    assert!(ran, "{json}");
    assert!(json.contains("\"disasm\":\"call sym._Z5riskyi\""), "{json}");
    assert!(json.contains("\"name\":\"sym._Z7guardedi\""), "{json}");
    assert!(!json.contains("risky(int)"), "{json}");
    let (ran, listing) = shell(true, "pdf @ sym._Z7guardedi");
    assert!(ran, "{listing}");
    assert!(listing.contains(": guarded(int) ("), "{listing}");
    assert!(listing.contains("call risky(int)"), "{listing}");
}
